curl -s -X POST -d '{"uniA" : "00000cc47a5e9895:3", "uniB" : "00000cc47a5e9894:3", "vlanid": 1688}' http://localhost:8080/sdnips/e-line/create | python -m json.tool
curl -s -X POST -d '{"uniA" : "00000cc47a5e9895:3", "uniB" : "00000cc47a5e9565:3", "vlanid": 1689}' http://localhost:8080/sdnips/e-line/create | python -m json.tool
curl -s -X POST -d '{"as_number" : 100, "router_id" : "192.168.1.1"}'    http://localhost:8080/sdnips/bgp/create | python -m json.tool
curl -s -X POST -d '{"prefix" : "192.168.100.0/24"}'    http://localhost:8080/sdnips/bgp/add_prefix | python -m json.tool
curl -s -X POST -d '{"remote_as" : 666, "address" : "192.168.1.2"}'    http://localhost:8080/sdnips/bgp/add_neighbor | python -m json.tool
