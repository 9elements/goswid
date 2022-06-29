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
	Debug         bool               `help:"Enable debug mode."`

	GenerateTagID generateTagIDCmd   `cmd help:"generates a 16 byte type-5 SHA1 RFC 4122 UUID (possible use for tag-id)"`
	Print         printCmd           `cmd help:"print swid tag to stdout (in json format)"`
	Convert       convertCmd         `cmd help:"convert between SWID/CoSWID and different file formats (json, xml, cbor, uswid)"`
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

func (c *convertCmd) Run() error {
	utag, err := importFiles(c.InputFiles, c.ParentTag)
	if err != nil {
		return err
	}

	// check file extension and put CoSWID tags into output file
	var output_buf []byte
	of_parts := strings.Split(c.OutputFile, ".")
	if len(of_parts) < 2 {
		return errors.New("no file extension found")
	}
	switch of_parts[len(of_parts)-1] {
	case "json":
		output_buf, err = utag.ToJSON()
	case "xml":
		output_buf, err = utag.ToXML()
	case "cbor":
		output_buf, err = utag.ToCBOR(c.ZlibCompress)
	case "uswid":
		output_buf, err = utag.ToUSWID(c.ZlibCompress)
	default:
		return errors.New("output file extension not supported")
	}
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(c.OutputFile, output_buf, 0644); err != nil {
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
