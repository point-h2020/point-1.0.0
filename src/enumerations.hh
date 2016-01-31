enum RootScopeNamespaces{
	NAMESPACE_IP=0,
	NAMESPACE_HTTP,
	NAMESPACE_COAP,
	NAMESPACE_UNKNOWN
};

enum MessageTypes
{
	//TODO migrate blackadder_defs.h to here
	ERROR=99,	/* using the codes in enum ErrorCodes below. Payload format:
	uint16_t, <ERROR_PAYLOAD>*/
};

enum ErrorCodes
{
	ICN_ID_NO_LONGER_AVAILABLE, /* A link went down and the link-local RV
	informs all its connected applications about an affected ICN ID. Multiple
	affected ICN IDs result in multiple messages using message type ERROR
	Payload format: string */
};
enum NODE_TYPE
{
    FW=0,
    RV,
    TM,
    NUM_TYPEs,
};