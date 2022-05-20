# HTTP Server
HTTP server implementation in C.
## TODO Tasks
- Fork Server
- Thread Server
- Pool Server
## Usage
1. Run server
- Build
```sh
$ make
```
- Directory mode:
```sh
$ ./httpserver --files any_directory/ [--port 8000 --num_threads 5]
```
- Proxy mode
```sh
$ ./httpserver --proxy any_url [--port 8000 --num_threads 5]
```
2. Run client
```sh
$ curl -o output.html -v http://192.168.162.162:8000/
```

# References
1. [CS162 HTTP hw] (https://cs162.org/static/hw/http.pdf)
