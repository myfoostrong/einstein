"""
Core structures / functionality for interfacing with a Philips IntelliVue Patient Monitor.

Based on the Philips Data Export Interface Programming Guide - id 4535 642 59271 - the "Philips Interface Programming Guide".
"""

from scapy.all import *
import float_type
from .const import *
from .common import *
from .protocol_command_structure import *
from .protocol_commands import *
from .association import *
from .attribute_data_types import *

PORT_CONNECTION_INDICATION = 24005  # PIPG-279
PORT_PROTOCOL = 24105  # PIPG-29




# TODO Relocate / flesh these out
NOM_MOC_VMO_METRIC_NU = 6
NOM_MOC_PT_DEMOG = 42
NOM_MOC_VMS_MDS = 33

bind_layers(Nomenclature, ROapdus)
bind_layers(SPpdu, ROapdus)
bind_layers(ROapdus, RORSapdu, ro_type=RORS_APDU)
bind_layers(ROapdus, ROIVapdu, ro_type=ROIV_APDU)
bind_layers(ROapdus, ROERapdu, ro_type=ROER_APDU)
bind_layers(ROapdus, ROLRSapdu, ro_type=ROLRS_APDU)
bind_layers(ROIVapdu, EventReportArgument, command_type=CMD_EVENT_REPORT)
bind_layers(ROIVapdu, EventReportArgument, command_type=CMD_CONFIRMED_EVENT_REPORT)
bind_layers(ROIVapdu, ActionArgument, command_type=CMD_CONFIRMED_ACTION)
bind_layers(RORSapdu, EventReportResult, command_type=CMD_CONFIRMED_EVENT_REPORT)
bind_layers(RORSapdu, ActionResult, command_type=CMD_CONFIRMED_ACTION)
bind_layers(ROLRSapdu, ActionResult, command_type=CMD_CONFIRMED_ACTION)
bind_layers(EventReportArgument, MDSCreateInfo, event_type=NOM_NOTI_MDS_CREAT)
bind_layers(ActionArgument, PollMdibDataReq, action_type=NOM_ACT_POLL_MDIB_DATA)
bind_layers(ActionArgument, PollMdibDataReqExt, action_type=NOM_ACT_POLL_MDIB_DATA_EXT)
bind_layers(ActionResult, PollMdibDataReply, action_type=NOM_ACT_POLL_MDIB_DATA)
bind_layers(ActionResult, PollMdibDataReplyExt, action_type=NOM_ACT_POLL_MDIB_DATA_EXT)
bind_layers(EventReportArgument, AttributeList, event_type=NOM_NOTI_MDS_CONNECT_INDIC)
bind_layers(AVAType, NuObsValue, attribute_id=NOM_ATTR_NU_VAL_OBS)
bind_layers(AVAType, AbsoluteTime, attribute_id=NOM_ATTR_TIME_STAMP_ABS)
bind_layers(AVAType, IpAddressInfo, attribute_id=NOM_ATTR_NET_ADDR_INFO)
bind_layers(AVAType, PollProfileSupport, attribute_id=NOM_POLL_PROFILE_SUPPORT)
bind_layers(AVAType, PollProfileExt, attribute_id=NOM_ATTR_POLL_PROFILE_EXT)

bind_layers(AVAType, AbsoluteTime, attribute_id=NOM_ATTR_PT_DOB)
bind_layers(AVAType, PatientType, attribute_id=NOM_ATTR_PT_TYPE)
bind_layers(AVAType, String, attribute_id=NOM_ATTR_PT_NAME_GIVEN)
bind_layers(AVAType, String, attribute_id=NOM_ATTR_PT_NAME_FAMILY)
bind_layers(AVAType, String, attribute_id=NOM_ATTR_PT_ID)
bind_layers(AVAType, String, attribute_id=NOM_ATTR_PT_SEX)
bind_layers(AVAType, PatMeasure, attribute_id=NOM_ATTR_PT_AGE)
bind_layers(AVAType, PatMeasure, attribute_id=NOM_ATTR_PT_WEIGHT)
bind_layers(AVAType, PatMeasure, attribute_id=NOM_ATTR_PT_HEIGHT)
bind_layers(AVAType, PatMeasure, attribute_id=NOM_ATTR_PT_BSA)
bind_layers(AVAType, String, attribute_id=NOM_ATTR_PT_NOTES1)
bind_layers(AVAType, String, attribute_id=NOM_ATTR_PT_NOTES2)
bind_layers(AVAType, PatDmgState, attribute_id=NOM_ATTR_PT_DEMOG_ST)

bind_layers(SessionHeader, AssocReqSessionData, type=CN_SPDU_SI)
bind_layers(AssocReqSessionData, AssocReqPresentationHeaderHeader)
bind_layers(AssocReqPresentationHeaderHeader, AssocReqPresentationHeaderData)
bind_layers(AssocReqPresentationHeaderData, AssocReqUserData)
bind_layers(AssocReqUserData, AssocReqPresentationTrailer)


if __name__ == '__main__':
    cieDump = '\x00\x00\x01\x00\x00\x01\x01\xc2\x00\x00\x00\x00\x01\xbc\x00#\x00\x00\x00\x00\x00\xd6\xd4\x00\r\x17\x01\xae\x00\x0b\x01\xaa\t \x00\x04\x00\x03\x00\x00\t\x86\x00\x04\x00\x01\x11M\t7\x00\x08\x06\x08\x06\x08\x00\x01\x00\x0b\xf1Z\x00\x04\x00\x00\x00\x02\xf16\x00\x04\x00\x00\x00\x00\xf2|\x00\x1a\x00\x01\x80\x00\x00\x01\x00\x12\xf1\x00\x00\x0e\x00\t\xfb\tw\xbd\n\r%\x02\xff\xff\xff\x00\xf15\x00"\x00E\x00C\x00C\x00 \x00M\x00O\x00N\x00 \x00R\x00M\x001\x005\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf1\x00\x00\x0e\x00\t\xfb\tw\xbd\n\r%\x02\xff\xff\xff\x00\xf1\x01\x00,\x00\x05\x00(\x00\x01\x00\x03]\xc0\x00\x00\x00\x02\x00\x03]\xc0\x00\x00\x00\x01\x00\x01^)\x00\x00\x00\x05\x00\x01^)\x00\x00\x00\x08\x00\x01\x825\x00\x00\t-\x00\xdc\x00\x06\x00d\x00\x01\x00\x08\x00\x0cDE22713007\x00\t\x00\x02\x00\x08\x00\x0eM8007A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x08\x00\x08 B.00.05\x00\x05\x00x\x00\x08--------\x00\x02\x00X\x00\x0eS-M4046-1701A \x00\x04\x00X\x00\x08G.01.78 \x00\x07\x00\x86\x00\x01\x00\x08\x00\x0cDE22713007\x00\t\x00\x02\x00\x08\x00\x0eM8007A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x08\x00\x08 B.00.05\x00\x05\x00x\x00\x08--------\x00\x02\x00X\x00\x0eS-M4046-1701A \x00\x04\x00X\x00\x08G.01.78 \x00\x02\x00X\x00\x0eS-M404\t(\x00\x14\x00\x08Philips\x00\x00\x07M8007A\x00\x00'

    print(cieDump)

    n = Nomenclature()
    n.dissect(cieDump)
    n.show()
