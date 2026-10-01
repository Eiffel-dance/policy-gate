from app import PolicyGate
p=PolicyGate([{'id':'read','effect':'allow','action':'read'},{'id':'prod-lock','effect':'deny','resource':'prod/*'}]); print(p.decide('alice','read','prod/db')); print(p.decide('alice','read','dev/db'))
