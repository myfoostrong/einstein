from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.web import server
import api
import datetime
import json
import socket
import intellivue as packets
import treq
import web
from util import json_serialize
import attr
import structlog
from scapy.utils import wrpcap
log = structlog.get_logger()
class IntellivueInterface(DatagramProtocol):
    """
    Handles communication with a Philips IntelliVue

    Currently a demo implementation - listens for existence announcements,
    associates, connects, and polls all connected monitors for basic data.

    The MAC address is the canonical form of monitor id;
    it's an (effectively) immutable property of the device.
    The IP address is what's actually used internally,
    because that's the layer things run at,
    but it's not exposed via the web API,
    and instead an internal DIY "ARP-alike" mapping is maintained.
    """

    def __init__(self, monitors=None, subscriptions=None, dumpfilename=None):
        self.monitors = monitors
        if self.monitors is None:
            self.monitors = {}  # Mapping of MAC -> api.Monitor

        self.subscriptions = subscriptions
        if self.subscriptions is None:
            self.subscriptions = {}  # Mapping of SubscriptionId -> Subscription

        self.dumpfilename = dumpfilename

        self.host_to_mac = {}
        self.associations = set()
        self.connections = set()


    def datagramReceived(self, data, addr):
        log.debug("Datagram received!", addr=addr)
        host, port = addr

        if port == packets.PORT_CONNECTION_INDICATION:
            self.handleConnectionIndication(data, addr)
        else:
            if data[0:2] == '\xe1\x00':  # PIPG-42
                self.handleProtocolMessage(data, addr)
            else:
                self.handleAssociationMessage(data, addr)


    def logPacket(self, packet):
        if self.dumpfilename is not None:
            wrpcap(self.dumpfilename, packet, append=True)


    def handleConnectionIndication(self, data, addr):
        ci = packets.ConnectIndication()
        ci.dissect(data)

        self.logPacket(ci)

        mac_address = ""
        if packets.IpAddressInfo in ci:
            mac_address = ci[packets.IpAddressInfo].mac_address
        else:
            log.warning("Could not extract MAC address from ConnectionIndication packet", addr=addr)
            return

        log.info("Received ConnectionIndication message", mac_address=mac_address, addr=addr)

        host, port = addr
        self.host_to_mac[host] = mac_address

        if self.monitors is not None:
            self.monitors[mac_address] = api.Monitor(mac_address=mac_address, host=host, port=port, last_seen=datetime.datetime.now())

        if host not in self.associations:
            log.info("Initiating Association!", mac_address=mac_address, host=host)
            self.sendAssociationRequest((host, packets.PORT_PROTOCOL))


    def sendAssociationRequest(self, addr):
        associationRequest = packets.SessionHeader(type=packets.CN_SPDU_SI)
        associationRequest /= packets.AssocReqSessionData()
        associationRequest /= packets.AssocReqPresentationHeaderHeader()
        associationRequest /= packets.AssocReqPresentationHeaderData()
        associationRequest /= packets.AssocReqUserData(
            MDSEUserInfoStd=packets.MDSEUserInfoStd(
                supported_aprofiles=packets.AttributeList(
                    value=[
                        packets.AVAType(
                            attribute_id=packets.NOM_POLL_PROFILE_SUPPORT,
                        ) /
                        packets.PollProfileSupport(
                            optional_packages=packets.AttributeList(
                                value=[
                                    packets.AVAType(
                                        attribute_id=packets.NOM_ATTR_POLL_PROFILE_EXT,
                                    ) /
                                    packets.PollProfileExt(
                                        options=packets.POLL_EXT_PERIOD_NU_1SEC|packets.POLL_EXT_PERIOD_RTSA|packets.POLL_EXT_ENUM,
                                    ),
                                ],
                            ),
                        ),
                    ],
                ),
            ),
        )
        associationRequest /= packets.AssocReqPresentationTrailer()

        associationRequest.show()
        associationRequest.show2()

        self.transport.write(str(associationRequest), addr)


    def handleAssociationMessage(self, data, addr):
        log.info("Received Association message", addr=addr)

        associationMessage = packets.SessionHeader()
        associationMessage.dissect(data)
        associationMessage.show()

        self.logPacket(associationMessage)

        t = associationMessage.type
        host, _ = addr
        if t == packets.AC_SPDU_SI:
            log.info("Received Association Confirmation!", host=host)
            self.associations.add(host)
        elif t in [packets.RF_SPDU_SI, packets.FN_SPDU_SI, packets.DN_SPDU_SI, packets.AB_SPDU_SI]:
            log.info("Dropping Association", host=host)
            self.associations.discard(host)

        # TODO Properly validate response, rejection, etc.


    def handleProtocolMessage(self, data, addr):
        log.debug("Received Protocol message, handling")
        message = packets.SPpdu()
        message.dissect(data)

        self.logPacket(message)

        host, _ = addr

        if packets.ROIVapdu in message:
            roivapdu = message[packets.ROIVapdu]

            if roivapdu.command_type == packets.CMD_CONFIRMED_EVENT_REPORT:
                log.info("Received MDSCreateEventReport, sending MDSCreateEventResult", addr=addr)

                # Ok! Now to reply!

                mdsceResult = packets.SPpdu()
                mdsceResult = mdsceResult / packets.ROapdus(ro_type=packets.RORS_APDU)
                mdsceResult = mdsceResult / packets.RORSapdu(
                    command_type=packets.CMD_CONFIRMED_EVENT_REPORT,
                    invoke_id=message[packets.ROIVapdu].invoke_id,
                )
                mdsceResult = mdsceResult / packets.EventReportResult(
                    managed_object=message[packets.EventReportArgument].managed_object,
                    event_type=packets.NOM_NOTI_MDS_CREAT,
                )

                self.transport.write(str(mdsceResult), addr)

                self.connections.add(host)
            else:
                log.warning("Unknown command_type in roivapdu!", addr=addr, roivapdu=roivapdu)
                roivapdu.show()
        elif packets.ROLRSapdu in message:
            # TODO Implement support for rolling up Remote Operation Linked Results
            log.debug("ROLRSapdu!")
            # message.show()
            self.handleResult(host, message)
        elif packets.ROERapdu in message:
            # Error
            message[packets.ROERapdu].show()
        elif packets.RORSapdu in message:
            log.debug("Results!")
            # message.show()
            self.handleResult(host, message)
        else:
            log.warning("Unknown message!")
            message.show()


    def pollConnectedHostsForData(self):
        for host in self.connections:
            self.pollForData((host, packets.PORT_PROTOCOL))


    def pollForData(self, addr):
        pollAction = packets.SPpdu()  # PIPG-55
        pollAction /= packets.ROapdus(ro_type=packets.ROIV_APDU)
        pollAction /= packets.ROIVapdu(command_type=packets.CMD_CONFIRMED_ACTION)
        pollAction /= packets.ActionArgument(
            managed_object=packets.ManagedObjectId(m_obj_class=packets.NOM_MOC_VMS_MDS),
            action_type=packets.NOM_ACT_POLL_MDIB_DATA_EXT,
        )
        pollAction /= packets.PollMdibDataReqExt(
            polled_obj_type=packets.TYPE(
                partition=packets.NOM_PART_OBJ,
                code=packets.NOM_MOC_PT_DEMOG,  # Numerics, i.e. numbers about attached patient
            ),
            polled_attr_grp=0,  # Show all data
        )

        # pollAction.show2()

        self.transport.write(str(pollAction), addr)

    def old_pollForData(self, addr):
        pollAction = packets.SPpdu()  # PIPG-55
        pollAction /= packets.ROapdus(ro_type=packets.ROIV_APDU)
        pollAction /= packets.ROIVapdu(command_type=packets.CMD_CONFIRMED_ACTION)
        pollAction /= packets.ActionArgument(
            managed_object=packets.ManagedObjectId(m_obj_class=packets.NOM_MOC_VMS_MDS),
            action_type=packets.NOM_ACT_POLL_MDIB_DATA_EXT,
        )
        pollAction /= packets.PollMdibDataReqExt(
            polled_obj_type=packets.TYPE(
                partition=packets.NOM_PART_OBJ,
                code=packets.NOM_MOC_VMO_METRIC_NU,  # Numerics, i.e. numbers about attached patient
            ),
            polled_attr_grp=packets.NOM_ATTR_GRP_METRIC_VAL_OBS,  # Observed values of the "object" (patient)
        )

        # pollAction.show2()

        self.transport.write(str(pollAction), addr)


    def displayResult(self, message):
        """
        This is quick and nasty and ignores all kinds of context, just focussing on ObservationPolls with data
        """

        poll_info_list = message[packets.PollInfoList]

        for single_context_poll in poll_info_list.value:
            for observation_poll in single_context_poll.value:
                for attribute_list in observation_poll.attributes:
                    for attribute in attribute_list.value:
                        if attribute.attribute_id == packets.NOM_ATTR_NU_VAL_OBS:
                            obsValue = attribute[packets.NuObsValue]
                            if obsValue.measurementIsValid():
                                obsValue.show()

    def handleResult(self, host, message):
        """
        We have PollInfo! Decide what to do with it based on polled_obj_type
        """

        for single_context_poll in message[packets.PollInfoList].value:
            for observation_poll in single_context_poll.value:
                for attribute_list in observation_poll.attributes:
                    obj_type = message[packets.PollMdibDataReplyExt].polled_obj_type
                    if obj_type.code == packets.NOM_MOC_PT_DEMOG:
                        self.handlePatientDemogResult(host, attribute_list)
                    elif obj_type.code == packets.NOM_MOC_VMO_METRIC_NU:
                        self.handleNumericResult(host, attribute_list)

    def handlePatientDemogResult(self, host, attribute_list):
        """
        We have Patient Data! Send appropriate webhooks
        """
        for attribute in attribute_list.value:
            # attribute.show()
            if attribute.attribute_id == packets.NOM_ATTR_PT_DOB:
                dob = attribute[packets.AbsoluteTime]
                dob_string = "%d/%d/%d" % (dob.month, dob.day, dob.year)
                # print(attribute.value)
            elif attribute.attribute_id == packets.NOM_ATTR_PT_TYPE:
                patient_type = attribute[packets.PatientType]
                # print(patient_type)
            elif attribute.attribute_id == packets.NOM_ATTR_PT_BSA:
                bsa = attribute[packets.PatMeasure].value
                # print(bsa)
            elif attribute.attribute_id == packets.NOM_ATTR_PT_DEMOG_ST:
                patient_state = attribute[packets.PatDmgState]
                # print(patient_state)
            elif attribute.attribute_id == packets.NOM_ATTR_PT_ID:
                patient_id = attribute[packets.String].value
                # print(patient_id)
            elif attribute.attribute_id == packets.NOM_ATTR_PT_NAME_FAMILY:
                family_name = attribute[packets.String].value
                # print(family_name)
            elif attribute.attribute_id == packets.NOM_ATTR_PT_NAME_GIVEN:
                given_name = attribute[packets.String].value
                # print(given_name)
            elif attribute.attribute_id == packets.NOM_ATTR_PT_SEX:
                sex = attribute[packets.String].value
                # print(sex)
            elif attribute.attribute_id == packets.NOM_ATTR_PT_AGE:
                age = attribute[packets.PatMeasure].value
                # print(age)
            elif attribute.attribute_id == packets.NOM_ATTR_PT_HEIGHT:
                height = attribute[packets.PatMeasure].value
                # print(height)
            elif attribute.attribute_id == packets.NOM_ATTR_PT_WEIGHT:
                weight = attribute[packets.PatMeasure].value
                # print(weight)
            elif attribute.attribute_id == packets.NOM_ATTR_PT_NOTES1:
                notes1 = attribute[packets.String].value
                # print(notes1)
            elif attribute.attribute_id == packets.NOM_ATTR_PT_NOTES2:
                notes2 = attribute[packets.String].value
                # print(notes2)
            # attribute.show()

        patient = api.Patient(
            dob=dob_string,
            patient_type=patient_type,
            bsa=bsa,
            patient_state=patient_state,
            patient_id=patient_id,
            family_name=family_name,
            given_name=given_name,
            sex=sex,
            age=age,
            height=height,
            weight=weight,
            notes1=notes1,
            notes2=notes2
        )
        print(patient)
        mac = self.host_to_mac[host]

        payload = api.Payload(
            monitor_id=mac,
            datetime=datetime.datetime.now(),
            observations=patient
        )

        for subscription in self.subscriptions.values():
            if subscription.monitor_id == mac:
                treq.post(subscription.url, data=json.dumps(attr.asdict(payload), default=json_serialize),
                          headers={b'Content-Type': [b'application/json']})


def handleNumericsResult(self, host, attribute_list):
        """
        We have results! Send appropriate webhooks
        """

        observations = []
        for attribute in attribute_list.value:
            if attribute.attribute_id == packets.NOM_ATTR_NU_VAL_OBS:
                obsValue = attribute[packets.NuObsValue]
                if obsValue.measurementIsValid():
                    states = []
                    for state in packets.ENUM_MEASUREMENT_STATE.keys():
                        if obsValue.state & state:
                            states.append(packets.ENUM_MEASUREMENT_STATE[state])
                    observation = api.Observation(
                        physio_id=packets.ENUM_IDENTIFIERS[obsValue.physio_id],
                        state=states,
                        unit_code=packets.ENUM_IDENTIFIERS[obsValue.unit_code],
                        value=obsValue.value,
                    )
                    observations.append(observation)

        if len(observations) == 0:
            log.debug("No valid measurements to send")
            return

        mac = self.host_to_mac[host]

        payload = api.Payload(
            monitor_id=mac,
            datetime=datetime.datetime.now(),
            observations=observations
        )

        for subscription in self.subscriptions.values():
            if subscription.monitor_id == mac:
                treq.post(subscription.url, data=json.dumps(attr.asdict(payload), default=json_serialize), headers={b'Content-Type': [b'application/json']})


    def startProtocol(self):
        self.loop = LoopingCall(self.pollConnectedHostsForData)
        self.loop.start(2)


    def stopProtocol(self):
        if self.loop is not None:
            self.loop.stop()


if __name__ == '__main__':
    monitors = {}
    subscriptions = {}
    w = web.EinsteinWebServer(monitors=monitors, subscriptions=subscriptions).app.resource()
    import os
    reactor.listenTCP(int(os.getenv("PORT", 8080)), server.Site(w))
    i = IntellivueInterface(monitors=monitors, subscriptions=subscriptions, dumpfilename=os.getenv("DUMPFILENAME"))
    reactor.listenUDP(packets.PORT_CONNECTION_INDICATION, i)

    log.info("Starting...")
    reactor.run()
