package uswid

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"io/ioutil"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/swid"
	"github.com/google/uuid"
)

var magic []byte = []byte{0x53, 0x42, 0x4F, 0x4D, 0xD6, 0xBA, 0x2E, 0xAC, 0xA3, 0xE6, 0x7A, 0x52, 0xAA, 0xEE, 0x3B, 0xAF} // can't be const...
const flagCompressZlib = 0x01

type UswidSoftwareIdentity struct {
	Identities []swid.SoftwareIdentity
}

func (uswid *UswidSoftwareIdentity) FromFile(filepath string) error {
	input_file, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}

	/* check file extension of input file */
	if_parts := strings.Split(filepath, ".")
	switch if_parts[len(if_parts)-1] {
	case "pc":
		pc_str := strings.ReplaceAll(string(input_file), "\r\n", "\n") // replace windows line endings with line feeds
		err = uswid.FromPC(pc_str, filepath)
	case "json":
		err = uswid.FromJSON(input_file)
	case "xml":
		err = uswid.FromXML(input_file)
	case "cbor":
		err = uswid.FromCBOR(input_file, false)
	case "uswid":
		fallthrough
	default:
		_, err = uswid.FromUSWID(input_file)
	}
	if err != nil {
		return fmt.Errorf("parsing %s: %w", filepath, err)
	}
	return nil
}

func (uswid *UswidSoftwareIdentity) FromCBOR(blob []byte, compressed bool) error {
	buf := bytes.NewBuffer(blob)
	var decoder *cbor.Decoder
	if compressed {
		rd, err := zlib.NewReader(buf)
		if err != nil {
			return fmt.Errorf("create zlib reader: %w", err)
		}
		decoder = cbor.NewDecoder(rd)
	} else {
		decoder = cbor.NewDecoder(buf)
	}
	for {
		var id swid.SoftwareIdentity
		err := decoder.Decode(&id)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("decoding cbor: %w", err)
		}
		uswid.Identities = append(uswid.Identities, id)
	}
	return nil
}

// returns the offset where the uswid data was found (first byte) in blob
func (uswid *UswidSoftwareIdentity) FromUSWID(blob []byte) (int, error) {
	var err error
	offset := bytes.Index(blob, magic)
	if offset == -1 {
		return -1, errors.New("could not find uswid data")
	}
	header_version := blob[offset+16]
	if header_version != 2 {
		return offset, errors.New("no known header version")
	}
	//header_len := binary.LittleEndian.Uint16(blob[offset+17:offset+19])
	payload_len := binary.LittleEndian.Uint32(blob[offset+19 : offset+23])
	flags := blob[offset+23]
	if (flags & flagCompressZlib) != 0 {
		err = uswid.FromCBOR(blob[offset+24:uint32(offset)+24+payload_len], true)
	} else {
		err = uswid.FromCBOR(blob[offset+24:uint32(offset)+24+payload_len], false)
	}
	if err != nil {
		return -1, fmt.Errorf("extract CBOR: %w", err)
	}
	return offset, nil
}

func (uswid *UswidSoftwareIdentity) FromJSON(json_data []byte) error {
	if len(json_data) == 0 {
		return errors.New("input data empty")
	}

	json_data = []byte(strings.TrimSpace(string(json_data)))

	if json_data[0] == '[' && json_data[len(json_data)-1] == ']' {
		var uswid_id UswidSoftwareIdentity
		if err := json.Unmarshal(json_data, &uswid_id.Identities); err != nil {
			return err
		}
		uswid.Identities = append(uswid.Identities, uswid_id.Identities...)
	} else {
		var id swid.SoftwareIdentity
		if err := id.FromJSON(json_data); err != nil {
			return err
		}
		uswid.Identities = append(uswid.Identities, id)
	}
	return nil
}

func (uswid *UswidSoftwareIdentity) FromXML(xml_data []byte) error {
	if len(xml_data) == 0 {
		return errors.New("input data empty")
	}

	var offset int64 = 0
	for offset < int64(len(xml_data)) {
		var id swid.SoftwareIdentity
		xml_decoder := xml.NewDecoder(bytes.NewReader(xml_data[offset:]))
		if err := xml_decoder.Decode(&id); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		uswid.Identities = append(uswid.Identities, id)
		offset += xml_decoder.InputOffset()
	}
	return nil
}

func (uswid *UswidSoftwareIdentity) FromPC(pc_data string, filename string) error {
	pc_lines := strings.Split(pc_data, "\n")
	var id swid.SoftwareIdentity
	var software_meta swid.SoftwareMeta
	for _, pc_line := range pc_lines {
		field := strings.Split(pc_line, ":")
		if (len(field) != 2) {
			continue
		}
		value := strings.TrimSpace(field[1])
		switch field[0] {
		case "Name":
			id.SoftwareName = value
		case "Description":
			software_meta.Summary = value
		case "Version":
			id.SoftwareVersion = value
		}
	}
	id.AddSoftwareMeta(software_meta)
	id.TagID = *swid.NewTagID(uuid.NewSHA1(uuid.NameSpaceDNS, []byte(filename)))
	if len(id.Entities) == 0 {
		entity, _ := swid.NewEntity("goswid (auto-generated)", swid.RoleTagCreator)
		id.AddEntity(*entity)
	}
	uswid.Identities = append(uswid.Identities, id)
	return nil
}

func (uswid UswidSoftwareIdentity) ToUSWID(compress bool) ([]byte, error) {
	var header [16 + 1 + 2 + 4 + 1]byte
	copy(header[:16], magic)                         // magic USWID value
	header[16] = 2                                   // header version
	binary.LittleEndian.PutUint16(header[17:19], 24) // header size

	header[23] = 0x00 // flags
	if compress {
		header[23] |= 0x01
	}
	cbor_buf, err := uswid.ToCBOR(compress)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(header[19:23], uint32(len(cbor_buf)))
	return append(header[:], cbor_buf...), nil
}

func (uswid UswidSoftwareIdentity) ToJSON() ([]byte, error) {
	var json_buf []byte
	if len(uswid.Identities) > 1 {
		json_buf = append(json_buf, '[')
		json_buf = append(json_buf, ' ')
	}
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
	if len(uswid.Identities) > 1 {
		json_buf = append(json_buf, ' ')
		json_buf = append(json_buf, ']')
	}
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

func (uswid UswidSoftwareIdentity) ToCBOR(compress bool) ([]byte, error) {
	var cbor_buf []byte
	for _, id := range uswid.Identities {
		buf, err := id.ToCBOR()
		if err != nil {
			return nil, fmt.Errorf("convert to CBOR: %w", err)
		}
		cbor_buf = append(cbor_buf, buf...)
	}
	if compress {
		var buf bytes.Buffer
		zlib_writer := zlib.NewWriter(&buf)
		_, err := zlib_writer.Write(cbor_buf)
		if err != nil {
			return nil, fmt.Errorf("cannot zlib compress CBOR data: %w", err)
		}
		zlib_writer.Close()
		return buf.Bytes(), nil
	} else {
		return cbor_buf, nil
	}
}
