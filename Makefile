.PHONY: e2ee-http

e2ee-http:
	/opt/homebrew/lib/ruby/gems/4.0.0/bin/kramdown-rfc e2ee-http/draft-vasylenko-e2ee-http-00.md > e2ee-http/draft-vasylenko-e2ee-http-00.xml
	xml2rfc --text --html e2ee-http/draft-vasylenko-e2ee-http-00.xml
