records = []
1.upto(25) do |i|
  records << %Q(
  {
  "name": "toomuchinfo-a.example.com",
  "type": "A",
  "ttl": 120,
  "data": {"ip": "192.168.99.#{i}"}
  },
  )
end

26.upto(90) do |i|
  records << %Q(
  {
  "name": "toomuchinfo-b.example.com",
  "type": "A",
  "ttl": 120,
  "data": {"ip": "192.168.99.#{i}"}
  },
  )
end
print records.join
print "\n"
