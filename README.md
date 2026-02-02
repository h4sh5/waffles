# WAFfles - a small simple WAF

A golang HTTP WAF that forwards requests to an origin URL after checking blocking rules.

It can act as a reverse proxy that functions as the web application's access point, blocking malicious requests.

Listens on port 80 by default.

## usage

### Compiling

`go build`

### Running

`./waffles <url of origin> <rules file>`

example (if origin URL is at `http://localhost:8080` and you are using the example rules)

`./waffles http://localhost:8080 example.rules.json`

### Rule writing

An example JSON rules file is provided in the repo.

Each rule has multiple items that combine using an OR / AND condition. Each rule item can be on the path (e.g. /admin), query (e.g. "id=1") or body (e.g. the body of a POST request), and uses Golang regex.

All rules are processed, and if any rules match the request will be blocked, returning HTTP status 406.

Example rule that blockes .. in path, query and body, and blocks HTML tags in query and `<script` in body (not taking in consideration HTTP encoding):

```json
[
	{
		"items": [
			{"id":"no-dot-dot-path", "part":"path", "regex":"\\.\\."},
			{"id":"no-dot-dot-query", "part":"query", "regex":"\\.\\."},
			{"id":"no-dot-dot-body", "part":"body", "regex":"\\.\\."}
		],
		"condition": "OR"
	},
	{
		"items": [
			{"id":"no-html-tag-query", "part":"query", "regex":"<"},
			{"id":"no-html-script-tag-body", "part":"body", "regex":"<script"}
		],
		"condition": "OR"
	}
]
```


