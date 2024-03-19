## Extracting JS files

#### Passive Mode - Using Wayback | Waymore

	1. echo hackerone.com | waybackurls | grep -iE '\.js' | grep -iEv '(\.jsp|\.json)' | anew js_wayback.txt

	2. echo hackerone.com | python ~/tools/waymore/waymore.py -mode U -oU js_waymore.txt && cat js_waymore.txt | grep -iE '\.js' | grep -iEv '(\.jsp|\.json)' | anew js_waym_final.txt

	3. cat js_wayback.txt  js_waym_final.txt | anew js_final.txt

#### Active Mode - using Katana

	cat domains.txt | katana -silent -jc | grep ".js$" | httpx -mc 200 | anew js.txt

---
## Searching for secrets in JS files

### Analyzing with Nuclei

	nuclei -l js.txt -t ~/nuclei-templates/exposures/ -o js_exposures_results.txt

### Analyzing with Regex

##### 1. Download all links in `js.txt` by doing

	file="js.txt";

	# Loop through each line in the file
	while IFS= read -r link; 
	do
		wget #$link" -P ~/path/to/save;
	done;

##### 2. Then run this

	find . -name "*.js" -print0 | xargs -0 -n 1 -P8 sh -c 'js-beautify "$1" | rg -e "(?i)((config|access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).*[\"]([0-9a-zA-Z\-_=]{8,64})[\"]"' xargs-sh

---
## Extracting from JS files

#### Extract URLs and Endpoints from JS files (No JS/JSON endpoint)

	find . -name "*.js" -print0 | xargs -0 -n1 -P8 sh -c 'js-beautify "$1" | rg -v "(nextjs\.org|reactjs\.org|angular\.io|fonts\.gstatic|instagram\.com|facebook\.com|twitter\.com|tiktok\.com|youtube\.com|w3\.org|\.js|\.json|\.css)" | rg -e "(http|https):\/\/[a-zA-Z0-9.\/?=_-]*"*' xargs-sh

If we need some context, we add `-o` flag on the last **rg** command.

---
### Finding hidden directory + hidden endpoint in JS codes with xnLinkFinder

	1. python xnLinkFinder.py -i target_js.txt -sf target.com -o js_final.txt
	2. httpx -l js_final.txt -mc 200

---
## Tips and Tricks

#### From Rhynorater

- Extract the HTML page that contains the dynamically generated JS file, extract the JS file name, open up the JS file, and then run a set of regexes on it and extract all the endpoints out.

#### Uncover APIs, Secrets etc with JSLuice - by Jayesh

- https://bishopfox.com/blog/jsluice-javascript-gold-mining - Parte I
- https://bishopfox.com/blog/jsluice-javascript-technical-deep-dive - Part II

1. Collect URLs from Katana and Waymore, then filter out .JS files.
2. Download those JS files using wget or curl and run JSLuice on them.
3. Filter the URLs extracted by JSLuice using keywords like Firebase, Amazon, CloudFront, Google Drive, etc. Manually investigate the results for bucket/cloud misconfigurations and report them for quick wins.
4. Repeat this process for other Interesting API endpoints, hardcoded credentials, and valuable data within JavaScript source code.

We can even create custom scripts to monitor JS files for changes, like new links, secrets, APIs, and more.

	jsluice urls fetch.js

	find . -name "*.js" | jsluice urls

---
### Check API  Token with Nuclei

	nuclei -t token-spray/ -var token=AIzaSyAQJMKEG9WDELbzJbv9bc80xpLMkyPvj9E

	https://developers.google.com/maps/documentation/maps-static/overview?hl=pt-br

---
## DOM-based Vulnerabilities

- **DOM-based DOS** can be induced if user-input lands in `requestFileSystem()` or
`RegExp()`
- **Client-side SQLi** can exist if user-input lands in `executeSql()` (database is created
via the `var db = openDatabase()` function, and later called via `db.transaction(function(tx) {tx.executeSql("...")})` )
- **DOM-based open redirection** can exist if user-input lands into one of the following sinks:

		location
		location.host
		location.hostname
		location.href
		location.pathname
		location.search
		location.protocol
		location.assign()
		location.replace()
		open()
		element.srcdoc
		XMLHttpRequest.open()
		XMLHttpRequest.send()
		jQuery.ajax()
		$.ajax()

- **DOM-based link manipulation** can be caused by one of the following sinks:

		element.href
		element.src
		element.action

- **DOM-based cookie manipulation** can exist if arbitrary user-input gets injected inside the `document.cookie` sink
- **DOM-based javascript injection** can be caused if user-input ends in one of the following sinks:

		eval()
		Function()
		setTImeout()
		setInterval()
		setImmediate()
		execCommand()
		execScript()
		msSetImmediate()
		range.createContextualFragment()
		crypto.generateCRMFRequest()

- **DOM-based local file-path manipulation** can be induced by one of the following sinks:

		FileReader.readAsArrayBuffer()
		FileReader.readAsBinaryString()
		FileReader.readAsDataURL()
		FileReader.readAsText()
		FileReader.readAsFile()
		FileReader.root.getFile()

- **DOM-based Ajax request-header manipulation** can be caused by one of the following sinks:

		XMLHttpRequest.setRequestHeader()
		XMLHttpRequest.open()
		XMLHttpRequest.send()
		jQuery.globalEval()
		$.globalEval()

---
## More Content

- https://realm3ter.medium.com/analyzing-javascript-files-to-find-bugs-820167476ffe - (X)
- https://www.youtube.com/watch?v=FTeE3OrTNoA - Hacker 101 - JavaScript - (X)
