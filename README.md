# goswid

This project is very similiar and intended to be compatible with [python-uswid](https://github.com/hughsie/python-uswid).

It's basically a tool to convert SWID (Software Identification Tags) and CoSWID (Consise Software Identification Tags) between different formats.

It's currently capable of converting SWID/CoSWID between JSON, XML, CBOR and uSWID+CBOR

If embedded into a coreboot build, one can use this tool to extract all SBOM Information out of an compiled coreboot image and save it in a format of choice. For example:
```sh
go run ./cmd/goswid convert -o sbom.json -i coreboot.rom
```

If one wants to include it into the build system of their application, one could do the following:
```sh
go run ./cmd/goswid convert -o final.json \
    --parent app.json \
    --requires dependency1.json dependency2.xml \
    --input tool1.xml app2.json \
    --compiler gcc.json
```
The parameters requires/input/compiler basically create a link between your application app.json and the other applications defined in the other SWID/CoSWID files. That makes it possible to represent a relationship between app.json and the other applications. These relationships include dependencies (--requires) and the compiler used to build the application (--compiler). You can also add CoSWID files without adding a relationship to the the main app.json (--input).
The relationships can for example be used for beautiful graphs or security audits.

pkg/uswid contains a simple/small uswid implementation and can be used by other go tools like it is used by goswid itself.

for more Information, see: [python-uswid](https://github.com/hughsie/python-uswid)
