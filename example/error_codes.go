package quic

const (
	QUIC_NO_ERROR = 0

	// Connection has reached an invalid state.
	QUIC_INTERNAL_ERROR = 1
	// There were data frames after the a fin or reset.
	QUIC_STREAM_DATA_AFTER_TERMINATION = 2
	// Control frame is malformed.
	QUIC_INVALID_PACKET_HEADER = 3
	// Frame data is malformed.
	QUIC_INVALID_FRAME_DATA = 4
	// The packet contained no payload.
	QUIC_MISSING_PAYLOAD = 48
	// FEC data is malformed.
	QUIC_INVALID_FEC_DATA = 5
	// STREAM frame data is malformed.
	QUIC_INVALID_STREAM_DATA = 46
	// STREAM frame data is not encrypted.
	QUIC_UNENCRYPTED_STREAM_DATA = 61
	// RST_STREAM frame data is malformed.
	QUIC_INVALID_RST_STREAM_DATA = 6
	// CONNECTION_CLOSE frame data is malformed.
	QUIC_INVALID_CONNECTION_CLOSE_DATA = 7
	// GOAWAY frame data is malformed.
	QUIC_INVALID_GOAWAY_DATA = 8
	// WINDOW_UPDATE frame data is malformed.
	QUIC_INVALID_WINDOW_UPDATE_DATA = 57
	// BLOCKED frame data is malformed.
	QUIC_INVALID_BLOCKED_DATA = 58
	// STOP_WAITING frame data is malformed.
	QUIC_INVALID_STOP_WAITING_DATA = 60
	// ACK frame data is malformed.
	QUIC_INVALID_ACK_DATA = 9

	// deprecated: QUIC_INVALID_CONGESTION_FEEDBACK_DATA = 47

	// Version negotiation packet is malformed.
	QUIC_INVALID_VERSION_NEGOTIATION_PACKET = 10
	// Public RST packet is malformed.
	QUIC_INVALID_PUBLIC_RST_PACKET = 11
	// There was an error decrypting.
	QUIC_DECRYPTION_FAILURE = 12
	// There was an error encrypting.
	QUIC_ENCRYPTION_FAILURE = 13
	// The packet exceeded kMaxPacketSize.
	QUIC_PACKET_TOO_LARGE = 14
	// Data was sent for a stream which did not exist.
	QUIC_PACKET_FOR_NONEXISTENT_STREAM = 15
	// The peer is going away.  May be a client or server.
	QUIC_PEER_GOING_AWAY = 16
	// A stream ID was invalid.
	QUIC_INVALID_STREAM_ID = 17
	// A priority was invalid.
	QUIC_INVALID_PRIORITY = 49
	// Too many streams already open.
	QUIC_TOO_MANY_OPEN_STREAMS = 18
	// The peer must send a FIN/RST for each stream and has not been doing so.
	QUIC_TOO_MANY_UNFINISHED_STREAMS = 66
	// Received public reset for this connection.
	QUIC_PUBLIC_RESET = 19
	// Invalid protocol version.
	QUIC_INVALID_VERSION = 20

	// deprecated: QUIC_STREAM_RST_BEFORE_HEADERS_DECOMPRESSED = 21

	// The Header ID for a stream was too far from the previous.
	QUIC_INVALID_HEADER_ID = 22
	// Negotiable parameter received during handshake had invalid value.
	QUIC_INVALID_NEGOTIATED_VALUE = 23
	// There was an error decompressing data.
	QUIC_DECOMPRESSION_FAILURE = 24
	// We hit our prenegotiated (or default) timeout
	QUIC_CONNECTION_TIMED_OUT = 25
	// We hit our overall connection timeout
	QUIC_CONNECTION_OVERALL_TIMED_OUT = 67
	// There was an error encountered migrating addresses
	QUIC_ERROR_MIGRATING_ADDRESS = 26
	// There was an error while writing to the socket.
	QUIC_PACKET_WRITE_ERROR = 27
	// There was an error while reading from the socket.
	QUIC_PACKET_READ_ERROR = 51
	// We received a STREAM_FRAME with no data and no fin flag set.
	QUIC_INVALID_STREAM_FRAME = 50
	// We received invalid data on the headers stream.
	QUIC_INVALID_HEADERS_STREAM_DATA = 56
	// The peer received too much data violating flow control.
	QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA = 59
	// The peer sent too much data violating flow control.
	QUIC_FLOW_CONTROL_SENT_TOO_MUCH_DATA = 63
	// The peer received an invalid flow control window.
	QUIC_FLOW_CONTROL_INVALID_WINDOW = 64
	// The connection has been IP pooled into an existing connection.
	QUIC_CONNECTION_IP_POOLED = 62
	// The connection has too many outstanding sent packets.
	QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS = 68
	// The connection has too many outstanding received packets.
	QUIC_TOO_MANY_OUTSTANDING_RECEIVED_PACKETS = 69
	// The quic connection job to load server config is cancelled.
	QUIC_CONNECTION_CANCELLED = 70
	// Disabled QUIC because of high packet loss rate.
	QUIC_BAD_PACKET_LOSS_RATE = 71

	// Crypto errors.

	// Hanshake failed.
	QUIC_HANDSHAKE_FAILED = 28
	// Handshake message contained out of order tags.
	QUIC_CRYPTO_TAGS_OUT_OF_ORDER = 29
	// Handshake message contained too many entries.
	QUIC_CRYPTO_TOO_MANY_ENTRIES = 30
	// Handshake message contained an invalid value length.
	QUIC_CRYPTO_INVALID_VALUE_LENGTH = 31
	// A crypto message was received after the handshake was complete.
	QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE = 32
	// A crypto message was received with an illegal message tag.
	QUIC_INVALID_CRYPTO_MESSAGE_TYPE = 33
	// A crypto message was received with an illegal parameter.
	QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER = 34
	// An invalid channel id signature was supplied.
	QUIC_INVALID_CHANNEL_ID_SIGNATURE = 52
	// A crypto message was received with a mandatory parameter missing.
	QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND = 35
	// A crypto message was received with a parameter that has no overlap
	// with the local parameter.
	QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP = 36
	// A crypto message was received that contained a parameter with too few
	// values.
	QUIC_CRYPTO_MESSAGE_INDEX_NOT_FOUND = 37
	// An internal error occured in crypto processing.
	QUIC_CRYPTO_INTERNAL_ERROR = 38
	// A crypto handshake message specified an unsupported version.
	QUIC_CRYPTO_VERSION_NOT_SUPPORTED = 39
	// There was no intersection between the crypto primitives supported by the
	// peer and ourselves.
	QUIC_CRYPTO_NO_SUPPORT = 40
	// The server rejected our client hello messages too many times.
	QUIC_CRYPTO_TOO_MANY_REJECTS = 41
	// The client rejected the server's certificate chain or signature.
	QUIC_PROOF_INVALID = 42
	// A crypto message was received with a duplicate tag.
	QUIC_CRYPTO_DUPLICATE_TAG = 43
	// A crypto message was received with the wrong encryption level (i.e. it
	// should have been encrypted but was not.)
	QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT = 44
	// The server config for a server has expired.
	QUIC_CRYPTO_SERVER_CONFIG_EXPIRED = 45
	// We failed to setup the symmetric keys for a connection.
	QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED = 53
	// A handshake message arrived but we are still validating the
	// previous handshake message.
	QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO = 54
	// A server config update arrived before the handshake is complete.
	QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE = 65
	// This connection involved a version negotiation which appears to have been
	// tampered with.
	QUIC_VERSION_NEGOTIATION_MISMATCH = 55

	// No error. Used as bound while iterating.
	QUIC_LAST_ERROR = 72
)
