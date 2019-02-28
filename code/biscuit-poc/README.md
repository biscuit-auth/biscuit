# Biscuit proof of concept

This project explores the issues encountered when implementing
Biscuit with the current design ideas.

## Storage format

### Block ordering and signature aggregation

The crypto designs do not impose any order on the blocks, which
might create issues with how each block is interpreted afterwards,
since they might rely on that order.

Solution: the blocks could contain an index, that would be checked
when deserializing.

### Separating the authority block from the rest

The authority block is the most critical one, since it defines
the starting rights.

We could make it a special case in the serialization format.

Or require that the block 0 be the authority block

### Two steps of deserialization

It might be easier to have a first step that deserializes
the keys and signature but keeps the blocks as byte arrays,
to check the signature, then deserializes the blocks to check
the caveats.

## datalog implementation

### Checking fact scope

We have to be very clear on the scope in which facts are created.
Authority facts can only be created by the authority blocks facts
and rules.
Ambient facts can only be created by the verifier.
Block facts cannot be in those scopes.

### Symbol table handling

To make the token smaller, we provide a "symbol" data type, which
is stored as an integer, but has a symbol table to map it to a string.
These symbols only support equality, set inclusion and set exclusion.

The symbol table is created by sending it a string, and if the string is
already present, we return its index, but if it's not, we append it to the list
and return its index.

The big issue here is that the symbol table has to be the same for the verifier
and for the block creator. Otherwise, some symbols in the block might map to
different strings than what the verifier thinks.

Right now, we have a default table containing some common symbols like "authority"
and "ambient". Then we add the new strings for the authority block.

Solution 1:
for each block, start from the default table with the authority symbols added. Then
add the symbols for the block (from its facts and rules). Then add the verifier's
facts and rules. Then run the caveat.

Solution 2:
start from the default table.
Add the symbols from the authority block.
Add the symbols from each block _in order_.
Add the symbols from the verifier
then for each block, start from there and add the verifier facts and rules and run the
caveats.
there should be no conflict with this way, but it relies on an order for the blocks.

### Adding a block requires knowing the previous ones

so that the symbol table is correct
