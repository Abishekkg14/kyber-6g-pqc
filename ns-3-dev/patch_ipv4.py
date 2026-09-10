import sys

f = '/home/force123/roshyy/Kyber-6G project/Kyber-6G project/ns-3-dev/src/internet/helper/ipv4-address-helper.cc'
with open(f, 'r') as file:
    content = file.read()

content = content.replace('Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();', 'Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>(); if (!ipv4) { std::cout << \"[DEBUG] Node ID \" << node->GetId() << \" lacks Ipv4 stack in Assign!\\\\n\"; }')

with open(f, 'w') as file:
    file.write(content)
