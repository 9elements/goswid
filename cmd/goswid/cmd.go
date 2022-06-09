package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"bytes"
	"encoding/json"

	"github.com/9elements/goswid/pkg/uswid"
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
	InputFiles   []string `arg required name:"input-file-paths" help:"Paths to imput files." type:"existingfile"`
	OutputFile	 string   `flag required short:"o" name:"output-file" help:"output file, either .json .xml .cbor or .uswid file" type:"path"`
	ZlibCompress bool     `flag optional short:"z" name:"zlib-compress" help:"zlib (RFC 1950) compress output, only possible with .uswid file as output" type:"path"`
}

type generateTagIDCmd struct {
	UuidgenName string   `flag required short:"n" name:"name" help:"string to use for uuid generation (e.g. software name)"`
}

type printCmd struct {
	InputFiles []string `arg required name:"input-file-paths" help:"Paths to imput files." type:"existingfile"`
}

func (c *convertCmd) Run() error {
	/* check file extension of output file */
	var err error
	var output_format FileType
	of_parts := strings.Split(c.OutputFile, ".")
	if len(of_parts) < 2 {
		return errors.New("no file extension found")
	}
	switch of_parts[len(of_parts)-1] {
	case "json":
		output_format = JSON
	case "xml":
		output_format = XML
	case "cbor":
		output_format = CBOR
	case "uswid":
		output_format = USWID
	default:
		return errors.New("output file extension not supported")
	}

	var uswid_input_tag uswid.UswidSoftwareIdentity
	for _, input_file_path := range c.InputFiles {
		input_file, err := ioutil.ReadFile(input_file_path)
		if err != nil {
			return err
		}

		/* check file extension of input file */
		if_parts := strings.Split(input_file_path, ".")
		switch if_parts[len(if_parts)-1] {
		case "pc":
			pc_str := strings.ReplaceAll(string(input_file), "\r\n", "\n") // replace windows line endings with line feeds
			err = uswid_input_tag.FromPC(pc_str, input_file_path)
		case "json":
			err = uswid_input_tag.FromJSON(input_file)
		case "xml":
			err = uswid_input_tag.FromXML(input_file)
		case "cbor":
			err = uswid_input_tag.FromCBOR(input_file, false)
		case "uswid":
			fallthrough
		default:
			_, err = uswid_input_tag.FromUSWID(input_file)
		}
		if err != nil {
			return fmt.Errorf("parsing %s: %w", input_file_path, err)
		}
	}
	var output_buf []byte
	switch output_format {
	case JSON:
		output_buf, err = uswid_input_tag.ToJSON()
	case XML:
		output_buf, err = uswid_input_tag.ToXML()
	case USWID:
		output_buf, err = uswid_input_tag.ToUSWID(c.ZlibCompress)
	case CBOR:
		output_buf, err = uswid_input_tag.ToCBOR(c.ZlibCompress)
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
	/* check file extension of output file */
	var uswid_input_tag uswid.UswidSoftwareIdentity
	for _, input_file_path := range p.InputFiles {
		input_file, err := ioutil.ReadFile(input_file_path)
		if err != nil {
			return err
		}

		/* check file extension of input file */
		if_parts := strings.Split(input_file_path, ".")
		switch if_parts[len(if_parts)-1] {
		case "pc":
			pc_str := strings.ReplaceAll(string(input_file), "\r\n", "\n") // replace windows line endings with line feeds
			err = uswid_input_tag.FromPC(pc_str, input_file_path)
		case "json":
			err = uswid_input_tag.FromJSON(input_file)
		case "xml":
			err = uswid_input_tag.FromXML(input_file)
		case "cbor":
			err = uswid_input_tag.FromCBOR(input_file, false)
		case "uswid":
			fallthrough
		default:
			_, err = uswid_input_tag.FromUSWID(input_file)
		}
		if err != nil {
			return fmt.Errorf("parsing %s: %w", input_file_path, err)
		}
	}
	output_buf, err := uswid_input_tag.ToJSON()
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

func (g *generateTagIDCmd) Run() error {
	fmt.Println(uuid.NewSHA1(uuid.NameSpaceDNS, []byte(g.UuidgenName)))
	return nil
}
