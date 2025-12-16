from typing import Union, Dict

class Protobuf:
    def __init__(self, data: Union[str, bytes] = None) -> None:
        self.buffer = bytearray()
        self.data = None
        self.pos = 0
        
        if data is not None:
            self.data = data.encode("latin-1") if isinstance(data, str) else data

    def reset(self) -> None:
        self.buffer = bytearray()

    def load_data(self, data: bytes) -> None:
        self.data, self.pos = data, 0
    
    def get_bytes(self) -> bytes:
        return bytes(self.buffer)
    
    def to_int(self, value: Union[int, str, bytes]) -> int:
        if isinstance(value, bytes):
            try:
                return int(value.decode("utf-8"))
            except:
                return int.from_bytes(value, "little")
        return int(value) if isinstance(value, str) else value

    def encode_varint(self, value: int) -> None:
        if value < 0:
            value = (1 << 64) + value
        
        while value > 0x7f:
            self.buffer.append(0x80 | (value & 0x7f))
            value >>= 7
        self.buffer.append(value & 0x7f)

    def encode_field_header(self, field_number: int, wire_type: int) -> None:
        self.encode_varint((field_number << 3) | wire_type)

    def encode_bytes(self, field_number: int, data: Union[str, bytes]) -> None:
        data = data.encode("utf-8") if isinstance(data, str) else data
        self.encode_field_header(field_number, 2)
        self.encode_varint(len(data))
        self.buffer.extend(data)

    def encode_message(self, field_number: int, message_bytes: Union[str, bytes]) -> None:
        self.encode_bytes(field_number, message_bytes)
    
    def encode_int(self, field_number: int, value: Union[int, str, bytes]) -> None:
        self.encode_field_header(field_number, 0)
        self.encode_varint(self.to_int(value))

    def encode_fixed64(self, field_number: int, value: Union[int, str, bytes]) -> None:
        self.encode_field_header(field_number, 1)
        self.buffer.extend(self.to_int(value).to_bytes(8, "little"))

    def decode_varint(self) -> int:
        result = shift = 0
        while self.pos < len(self.data):
            byte = self.data[self.pos]
            result |= (byte & 0x7f) << shift
            self.pos += 1

            if not (byte & 0x80):
                return result

            shift += 7
        return result

    def decode_bytes(self) -> bytes:
        length = self.decode_varint()
        result = self.data[self.pos:self.pos + length]
        self.pos += length
        return result
    
    def decode_fixed(self, size: int) -> int:
        result = int.from_bytes(self.data[self.pos:self.pos + size], "little")
        self.pos += size
        return result
    
    def decode_fixed32(self) -> int:
        return self.decode_fixed(4)
    
    def decode_fixed64(self) -> int:
        return self.decode_fixed(8)

    def decode_message(self) -> Dict[int, Union[int, bytes]]:
        decoders: dict = {
            0: self.decode_varint,
            1: self.decode_fixed64,
            2: self.decode_bytes,
            5: self.decode_fixed32
        }

        fields: dict = {}
        while self.pos < len(self.data):
            tag = self.decode_varint()
            field_number, wire_type = tag >> 3, tag & 0x7

            if wire_type in decoders:
                fields[field_number] = decoders[wire_type]()

        return fields