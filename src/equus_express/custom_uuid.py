import uuid

def encode_custom_uuid(message_type, slot, io_type, io_index, prefix_bytes=None):
    """
    Encode the given fields into a UUID.
    - prefix_bytes: optional 12-byte prefix; if None, use random bytes.
    Returns: uuid.UUID instance
    """
    if not (0 <= message_type < 256 and 0 <= slot < 256 and 0 <= io_type < 256 and 0 <= io_index < 256):
        raise ValueError("All fields must be 0-255")
    if prefix_bytes is None:
        prefix_bytes = uuid.uuid4().bytes[:12]
    if len(prefix_bytes) != 12:
        raise ValueError("prefix_bytes must be 12 bytes")
    b = bytearray(prefix_bytes)
    b.extend([message_type, slot, io_type, io_index])
    return uuid.UUID(bytes=bytes(b))

def decode_custom_uuid(u):
    """
    Decode the last 4 bytes of the UUID and return (message_type, slot, io_type, io_index)
    u: uuid.UUID or 16-byte object
    """
    if isinstance(u, uuid.UUID):
        b = u.bytes
    elif isinstance(u, (bytes, bytearray)) and len(u) == 16:
        b = u
    else:
        raise ValueError("Input must be a uuid.UUID or 16 bytes")
    return tuple(b[-4:])  # (message_type, slot, io_type, io_index)

def to_binary(u):
    if isinstance(u, uuid.UUID):
        return u.bytes
    raise ValueError("Input must be uuid.UUID")

def from_binary(b):
    return uuid.UUID(bytes=b)

def to_text(u):
    if isinstance(u, uuid.UUID):
        return str(u)
    raise ValueError("Input must be uuid.UUID")

def from_text(s):
    return uuid.UUID(s)
