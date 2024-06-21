# Convert RSSI hex byte to dBm
# The calibrated signal strength is a one byte signed integer.
# To convert it to a signed decimal number, first convert it to
# an unsigned decimal, then if it is > 127 subtract 128.
# C5 Hex -> 197 Unsigned Decimal -> -59 Signed Decimal
# The units are dBm, more negative numbers represent weaker signals.
# Less negative numbers represent stronger signals.
def rssi_to_dbm(rssi):
    aux = int(rssi, 16)
    dbm = aux - 128 if aux > 127 else aux
    return dbm

# Convert endianess 0x1a2b3c to [0x3c, 0x2b, 0x1a] keeping it in hex
# Separate each byte from the array and reverse it
# Return as in 0x format
def stream_to_bytes(stream):
    bytes_array = [stream[i:i+2] for i in range(0, len(stream), 2)]
    bytes_array.reverse()
    # Return as in 0x format
    bytes_array = [int(byte, 16) for byte in bytes_array]
    bytes_array = '0x' + ''.join([format(byte, '02x') for byte in bytes_array])
    return bytes_array