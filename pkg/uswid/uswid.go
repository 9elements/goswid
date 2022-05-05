package uswid

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/veraison/swid"
	"github.com/fxamacker/cbor/v2"
)

var magic []byte = []byte{0x53, 0x42, 0x4F, 0x4D, 0xD6, 0xBA, 0x2E, 0xAC, 0xA3, 0xE6, 0x7A, 0x52, 0xAA, 0xEE, 0x3B, 0xAF} // can't be const...
const flagCompress = 0x01

type UswidSoftwareIdentity struct {
	Identities []swid.SoftwareIdentity
}

func (uswid *UswidSoftwareIdentity) fromCBOR() (offset int, err error) {
	//TODO
	return 0, nil
}

// returns the offset where the uswid data was found (first byte) in blob
func (uswid *UswidSoftwareIdentity) FromUSWID(blob []byte) (offset int, err error) {
	offset = bytes.Index(blob, magic)
	if offset == -1 {
		return -1, errors.New("could not find uswid data")
	}
	header_version := blob[offset+16]
	if header_version != 2 {
		return -1, errors.New("no known header version")
	}
	//header_len := binary.LittleEndian.Uint16(blob[offset+17:offset+19])
	payload_len := binary.LittleEndian.Uint32(blob[offset+19:offset+23])
	flags := blob[offset+23]
	if (flags & flagCompress) != 0 {
		buf := bytes.NewBuffer(blob[offset+24:uint32(offset)+24+payload_len])
		rd, err := zlib.NewReader(buf)
		defer rd.Close()
		if err != nil {
			return -1, fmt.Errorf("create zlib reader: %w", err)
		}
		// we can't just use id.FromCBOR, since we will not know the size of the
		// CBOR payload like that. but we need the size, otherwise we don't know
		// the offset to the next CBOR payload. so we need to create the
		// CBOR decoder ourselfs instead of using github.com/veraison/swid
		decoder := cbor.NewDecoder(rd)
		for uint32(decoder.NumBytesRead()) < payload_len {
			var id swid.SoftwareIdentity
			err = decoder.Decode(&id)
			if err != nil {
				return offset, fmt.Errorf("decoding cbor: %w", err)
			}
			uswid.Identities = append(uswid.Identities, id)
		}
	} else {
		//err = uswid.FromCBOR(blob[offset+24:uint32(offset)+24+payload_len])
		rd := bytes.NewBuffer(blob[offset+24:uint32(offset)+24+payload_len])
		if err != nil {
			return -1, fmt.Errorf("create zlib reader: %w", err)
		}
		decoder := cbor.NewDecoder(rd)
		for uint32(decoder.NumBytesRead()) < payload_len {
			var id swid.SoftwareIdentity
			err = decoder.Decode(&id)
			if err != nil {
				return offset, fmt.Errorf("decoding cbor: %w", err)
			}
			uswid.Identities = append(uswid.Identities, id)
		}
	}
	if err != nil {
		return -1, fmt.Errorf("extract CBOR: %w", err)
	}
	if len(uswid.Identities) == 0 {
		return -1, errors.New("malformed uswid or uswid contains no data")
	}
	return offset, nil
}

func (uswid UswidSoftwareIdentity) ToUSWID(compress bool) ([]byte, error) {
	var header [16+1+2+4+1]byte
	copy(header[:16], magic) // magic USWID value
	header[16] = 2 // header version
	binary.LittleEndian.PutUint16(header[17:19], 24) // header size

	header[23] = 0x00 // flags
	var cbor_writer bytes.Buffer
	if compress {
		header[23] |= 0x01
		zlib_writer := zlib.NewWriter(&cbor_writer)
		defer zlib_writer.Close()
		enc := cbor.NewEncoder(zlib_writer)
		for _, id := range uswid.Identities {
			err := enc.Encode(id)
			if err != nil {
				return nil, fmt.Errorf("cbor encode: %w", err)
			}
		}
		binary.LittleEndian.PutUint32(header[19:23], uint32(cbor_writer.Len()))
	} else {
		enc := cbor.NewEncoder(&cbor_writer)
		for _, id := range uswid.Identities {
			err := enc.Encode(id)
			if err != nil {
				return nil, fmt.Errorf("cbor encode: %w", err)
			}
		}
		binary.LittleEndian.PutUint32(header[19:23], uint32(cbor_writer.Len()))
	}
	return append(header[:], cbor_writer.Bytes()...), nil
}

func (uswid UswidSoftwareIdentity) ToJSON() ([]byte, error) {
	var json_buf []byte
	json_buf = append(json_buf, '[')
	json_buf = append(json_buf, ' ')
	for i, id := range uswid.Identities {
		buf, err := id.ToJSON()
		if err != nil {
			return nil, fmt.Errorf("convert to JSON: %w", err)
		}
		json_buf = append(json_buf, buf...)
		if i < len(uswid.Identities)-1 {
			json_buf = append(json_buf, ',')
		}
	}
	json_buf = append(json_buf, ' ')
	json_buf = append(json_buf, ']')
	return json_buf, nil
}

func (uswid UswidSoftwareIdentity) ToXML() ([]byte, error) {
	var xml_buf []byte
	for _, id := range uswid.Identities {
		id.XMLName.Space = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
		id.XMLName.Local = "SoftwareIdentity"

		buf, err := id.ToXML()
		if err != nil {
			return nil, fmt.Errorf("convert to XML: %w", err)
		}
		xml_buf = append(xml_buf, buf...)
	}
	return xml_buf, nil
}

func (uswid UswidSoftwareIdentity) ToCBOR() ([]byte, error) {
	var cbor_buf []byte
	for _, id := range uswid.Identities {
		buf, err := id.ToCBOR()
		if err != nil {
			return nil, fmt.Errorf("convert to CBOR: %w", err)
		}
		cbor_buf = append(cbor_buf, buf...)
	}
	return cbor_buf, nil
}
