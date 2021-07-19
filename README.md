# Digital-Covid-Certificate Decoder

This is a simple tool to decode the text in the QR-Codes of digital covid certificates

## Basic Usage

```sh
$ echo "HC1:…" | dcc-decode
```

## Advanced usage

```sh
$ git clone https://github.com/ehn-dcc-development/ehn-dcc-valuesets.git
$ curl https://de.dscg.ubirch.com/trustList/DSC/ | sed '1d' > trustlist.json
$ echo "HC1:…" | dcc-decode
```

## Additional Options

- `--json` to print out the [JSON version of the DCC][ehn-dcc]

[ehn-dcc]: https://ec.europa.eu/health/sites/default/files/ehealth/docs/covid-certificate_json_specification_en.pdf