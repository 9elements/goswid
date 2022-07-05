package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/9elements/goswid/pkg/uswid"
	"github.com/veraison/swid"
	"github.com/google/uuid"
)

type FileType int

const (
	JSON FileType = iota
	XML
	CBOR
	USWID
)

var cli struct {
	Debug         bool               `help:"Enable debug mode"`

	GenerateTagID  generateTagIDCmd  `cmd help:"generates a 16 byte type-5 SHA1 RFC 4122 UUID (possible use for tag-id)"`
	Print          printCmd          `cmd help:"print swid tag to stdout (in json format)"`
	Convert        convertCmd        `cmd help:"convert between SWID/CoSWID and different file formats (json, xml, cbor, uswid)"`
	AddPayloadFile addPayloadFileCmd `cmd help:"add payload file into an existing CoSWID tag"`

}

type addPayloadFileCmd struct {
	PayloadFileName	string `flag required long:"name" name:"payload-file" help:"filename that should be added to the payload portion of the CoSWID tag"`
	InputFile   string `flag required short:"i" name:"input-file" help:"Path to imput files." type:"existingfile"`
	OutputFile	string `flag required short:"o" name:"output-file" help:"output file, either .json .xml .cbor or .uswid file" type:"path"`
}

type convertCmd struct {
	ParentTag      bool `flag optional short:"p" name:"parent-file" help:"It is assumed that for all supplied files, the first tag of each file is a parent tag. goswid will automatically add a link (with dependency link type) between the first given uSWID/CoSWID Tag and all other parent tags"`
	InputFiles   []string `arg required name:"input-file-paths" help:"Paths to imput files." type:"existingfile"`
	OutputFile	 string   `flag required short:"o" name:"output-file" help:"output file, either .json .xml .cbor or .uswid file" type:"path"`
	ZlibCompress bool     `flag optional short:"z" name:"zlib-compress" help:"zlib (RFC 1950) compress output, only possible with .uswid file as output" type:"path"`
}

type generateTagIDCmd struct {
	UuidgenName string   `flag required short:"n" name:"name" help:"string to use for uuid generation (e.g. software name)"`
}

type printCmd struct {
	ParentTag      bool `flag optional short:"p" name:"parent-file" help:"It is assumed that for all supplied files, the first tag of each file is a parent tag. goswid will automatically add a link (with dependency link type) between the first given uSWID/CoSWID Tag and all other parent tags"`
	InputFiles []string `arg required name:"input-file-paths" help:"Paths to imput files." type:"existingfile"`
}

func (a *addPayloadFileCmd) Run() error {
	var utag uswid.UswidSoftwareIdentity
	//TODO program FromFile in swid library
	err := utag.FromFile(a.InputFile)
	if err != nil {
		return err
	}
	if len(utag.Identities) != 1 {
		return fmt.Errorf("uSWID file has %d CoSWID Identities, want only 1 Identity", len(utag.Identities))
	}

	var f swid.File
	//f.Key = &key
	//f.Location = location
	f.FsName = a.PayloadFileName
	//f.Root = root
	//f.Size = &size
	//f.FileVersion = fileVersion
	//f.Hash.HashAlgID = hashAlgID
	//f.Hash.HashValue = hashValue
	payload := swid.NewPayload()
	payload.AddFile(f)
	utag.Identities[0].Payload = payload

	if err := writeFile(a.OutputFile, false, utag); err != nil {
		return err
	}
	return nil
}

func (c *convertCmd) Run() error {
	utag, err := importFiles(c.InputFiles, c.ParentTag)
	if err != nil {
		return err
	}
	if err := writeFile(c.OutputFile, c.ZlibCompress, *utag); err != nil {
		return err
	}
	return nil
}

func (p *printCmd) Run() error {
	utag, err := importFiles(p.InputFiles, p.ParentTag)
	if err != nil {
		return err
	}

	output_buf, err := utag.ToJSON()
	if err != nil {
		return fmt.Errorf("uswid_input_tag.ToJSON(): %w", err)
	}
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, []byte(output_buf), "", "    "); err != nil {
		return err
	}

	fmt.Println(prettyJSON.String())
	return nil
}

func (g *generateTagIDCmd) Run() {
	fmt.Println(uuid.NewSHA1(uuid.NameSpaceDNS, []byte(g.UuidgenName)))
}

func writeFile(filename string, zlib_compress bool, utag uswid.UswidSoftwareIdentity) error {
	// check file extension and put CoSWID tags into output file
	var output_buf []byte
	of_parts := strings.Split(filename, ".")
	if len(of_parts) < 2 {
		return errors.New("no file extension found")
	}

	var err error
	switch of_parts[len(of_parts)-1] {
	case "json":
		output_buf, err = utag.ToJSON()
	case "xml":
		output_buf, err = utag.ToXML()
	case "cbor":
		output_buf, err = utag.ToCBOR(zlib_compress)
	case "uswid":
		output_buf, err = utag.ToUSWID(zlib_compress)
	default:
		return errors.New("output file extension not supported")
	}
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(filename, output_buf, 0644); err != nil {
		return err
	}
	return nil
}

func importFiles(filepaths []string, parentTag bool) (*uswid.UswidSoftwareIdentity, error) {
	var utag uswid.UswidSoftwareIdentity
	for _, input_file_path := range filepaths {
		first_tag_of_file := len(utag.Identities)
		if err := utag.FromFile(input_file_path); err != nil {
			return nil, err
		}
		// if there is a topfile specified, we create a link between that CoSWID tag and the first of each file, which we assume to be a parent CoSWID Tag above all others
		if parentTag && first_tag_of_file > 0 {
			stag := &utag.Identities[0]
			required_tag := utag.Identities[first_tag_of_file]

			link, err := swid.NewLink(required_tag.TagID.URI(), *swid.NewRel(swid.RelRequires))
			if err != nil {
				return nil, err
			}
			if err := stag.AddLink(*link); err != nil {
				return nil, err
			}
		}
	}
	return &utag, nil
}
