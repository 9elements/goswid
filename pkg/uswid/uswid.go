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
	"github.com/CodingVoid/swid"
	"github.com/google/uuid"
)

var magic []byte = []byte{0x53, 0x42, 0x4F, 0x4D, 0xD6, 0xBA, 0x2E, 0xAC, 0xA3, 0xE6, 0x7A, 0x52, 0xAA, 0xEE, 0x3B, 0xAF} // can't be const...
const flagCompressZlib = 0x01

// uSWID is essentially supposed to be a collection of CoSWID/SWID tags.
type UswidSoftwareIdentity struct {
	Identities []swid.SoftwareIdentity
}

func (uswid *UswidSoftwareIdentity) FromFile(filepath string) error {
	inputFile, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}

	/* check file extension of input file */
	ifParts := strings.Split(filepath, ".")
	switch ifParts[len(ifParts)-1] {
	case "pc":
		pcStr := strings.ReplaceAll(string(inputFile), "\r\n", "\n") // replace windows line endings with line feeds
		err = uswid.FromPC(pcStr, filepath)
	case "json":
		err = uswid.FromJSON(string(inputFile))
	case "xml":
		err = uswid.FromXML(string(inputFile))
	case "cbor":
		err = uswid.FromCBOR(inputFile, false)
	case "uswid":
		fallthrough
	default:
		_, err = uswid.FromUSWID(inputFile)
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
	headerVersion := blob[offset+16]
	if headerVersion != 2 {
		return offset, errors.New("no known header version")
	}
	//header_len := binary.LittleEndian.Uint16(blob[offset+17:offset+19])
	payloadLen := binary.LittleEndian.Uint32(blob[offset+19 : offset+23])
	flags := blob[offset+23]
	if (flags & flagCompressZlib) != 0 {
		err = uswid.FromCBOR(blob[offset+24:uint32(offset)+24+payloadLen], true)
	} else {
		err = uswid.FromCBOR(blob[offset+24:uint32(offset)+24+payloadLen], false)
	}
	if err != nil {
		return -1, fmt.Errorf("extract CBOR: %w", err)
	}
	return offset, nil
}

func (uswid *UswidSoftwareIdentity) FromJSON(jsonStr string) error {
	if len(jsonStr) == 0 {
		return errors.New("input data empty")
	}

	jsonStr = strings.TrimSpace(jsonStr)

	if jsonStr[0] == '[' && jsonStr[len(jsonStr)-1] == ']' {
		var uswidID UswidSoftwareIdentity
		if err := json.Unmarshal([]byte(jsonStr), &uswidID.Identities); err != nil {
			return err
		}
		uswid.Identities = append(uswid.Identities, uswidID.Identities...)
	} else {
		var id swid.SoftwareIdentity
		if err := id.FromJSON([]byte(jsonStr)); err != nil {
			return err
		}
		uswid.Identities = append(uswid.Identities, id)
	}
	return nil
}

func (uswid *UswidSoftwareIdentity) FromXML(xmlStr string) error {
	if len(xmlStr) == 0 {
		return errors.New("input data empty")
	}

	var offset int64 = 0
	for offset < int64(len(xmlStr)) {
		var id swid.SoftwareIdentity
		xmlDecoder := xml.NewDecoder(bytes.NewReader([]byte(xmlStr[offset:])))
		if err := xmlDecoder.Decode(&id); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		uswid.Identities = append(uswid.Identities, id)
		offset += xmlDecoder.InputOffset()
	}
	return nil
}

func (uswid *UswidSoftwareIdentity) FromPC(pcData string, filename string) error {
	pcLines := strings.Split(pcData, "\n")
	var id swid.SoftwareIdentity
	var softwareMeta swid.SoftwareMeta
	for _, pcLine := range pcLines {
		field := strings.Split(pcLine, ":")
		if (len(field) != 2) {
			continue
		}
		value := strings.TrimSpace(field[1])
		switch field[0] {
		case "Name":
			id.SoftwareName = value
		case "Description":
			softwareMeta.Summary = value
		case "Version":
			id.SoftwareVersion = value
		}
	}
	id.AddSoftwareMeta(softwareMeta)
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
	cborBuf, err := uswid.ToCBOR(compress)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(header[19:23], uint32(len(cborBuf)))
	return append(header[:], cborBuf...), nil
}

func (uswid UswidSoftwareIdentity) ToJSON() ([]byte, error) {
	var jsonBuf []byte
	if len(uswid.Identities) > 1 {
		jsonBuf = append(jsonBuf, '[')
		jsonBuf = append(jsonBuf, ' ')
	}
	for i, id := range uswid.Identities {
		buf, err := id.ToJSON()
		if err != nil {
			return nil, fmt.Errorf("convert to JSON: %w", err)
		}
		jsonBuf = append(jsonBuf, buf...)
		if i < len(uswid.Identities)-1 {
			jsonBuf = append(jsonBuf, ',')
		}
	}
	if len(uswid.Identities) > 1 {
		jsonBuf = append(jsonBuf, ' ')
		jsonBuf = append(jsonBuf, ']')
	}
	return jsonBuf, nil
}

func (uswid UswidSoftwareIdentity) ToXML() ([]byte, error) {
	var xmlBuf []byte
	for _, id := range uswid.Identities {
		id.XMLName.Space = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
		id.XMLName.Local = "SoftwareIdentity"

		buf, err := id.ToXML()
		if err != nil {
			return nil, fmt.Errorf("convert to XML: %w", err)
		}
		xmlBuf = append(xmlBuf, buf...)
	}
	return xmlBuf, nil
}

func (uswid UswidSoftwareIdentity) ToCBOR(compress bool) ([]byte, error) {
	var cborBuf []byte
	for _, id := range uswid.Identities {
		buf, err := id.ToCBOR()
		if err != nil {
			return nil, fmt.Errorf("convert to CBOR: %w", err)
		}
		cborBuf = append(cborBuf, buf...)
	}
	if compress {
		var buf bytes.Buffer
		zlibWriter := zlib.NewWriter(&buf)
		_, err := zlibWriter.Write(cborBuf)
		if err != nil {
			return nil, fmt.Errorf("cannot zlib compress CBOR data: %w", err)
		}
		zlibWriter.Close()
		return buf.Bytes(), nil
	} else {
		return cborBuf, nil
	}
}
