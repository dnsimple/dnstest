records = []
0.upto(19999) do |i|
  records << %Q(
 {
  "name": "host-#{i}.example.com",
  "type": "A",
  "ttl": 120,
  "data": {"ip": "192.168.1.#{i % 256}"}
  },
  )
end
print records.join
print "\n"
