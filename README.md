
# biscuit-go

biscuit-go is an implementation of [Biscuit](https://github.com/eclipse-biscuit/biscuit) in Go. It aims to be fully compatible with other existing implementations, so that tokens issued by, for example, the Rust version, could be validated by this library and vice versa.

## Documentation and specifications

- [biscuit website](https://www.biscuitsec.org) for documentation and examples
- [biscuit specification](https://github.com/eclipse-biscuit/biscuit)
- [biscuit-rust](https://github.com/eclipse-biscuit/biscuit-rust) for some more technical details.

## Usage

#### Create a biscuit
```go
rng := rand.Reader
publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

authority, err := parser.FromStringBlockWithParams(`
	right("/a/file1.txt", {read});
	right("/a/file1.txt", {write});
	right("/a/file2.txt", {read});
	right("/a/file3.txt", {write});
`, map[string]biscuit.Term{"read": biscuit.String("read"), "write": biscuit.String("write")})

if err != nil {
	panic(fmt.Errorf("failed to parse authority block: %v", err))
}

builder := biscuit.NewBuilder(privateRoot)
builder.AddBlock(authority)

b, err := builder.Build()
if err != nil {
	panic(fmt.Errorf("failed to build biscuit: %v", err))
}

token, err := b.Serialize()
if err != nil {
	panic(fmt.Errorf("failed to serialize biscuit: %v", err))
}

// token is now a []byte, ready to be shared
// The biscuit spec mandates the use of URL-safe base64 encoding for textual representation:
fmt.Println(base64.URLEncoding.EncodeToString(token))
```

#### Attenuate a biscuit

```go
b, err = biscuit.Unmarshal(token)
if err != nil {
    panic(fmt.Errorf("failed to deserialize biscuit: %v", err))
}

// Attenuate the biscuit by appending a new block to it
blockBuilder := b.CreateBlock()
block, err := parser.FromStringBlockWithParams(`
		check if resource($file), operation($permission), [{read}].contains($permission);`,
	map[string]biscuit.Term{"read": biscuit.String("read")})
if err != nil {
	panic(fmt.Errorf("failed to parse block: %v", err))
}
blockBuilder.AddBlock(block)

attenuatedBiscuit, err := b.Append(rng, blockBuilder.Build())
if err != nil {
    panic(fmt.Errorf("failed to append: %v", err))
}
attenuatedToken, err := b.Serialize()
if err != nil {
    panic(fmt.Errorf("failed to serialize biscuit: %v", err))
}

// attenuatedToken is a []byte, representing an attenuated token
```

#### Verify a biscuit

```go
b, err := biscuit.Unmarshal(token)
if err != nil {
    panic(fmt.Errorf("failed to deserialize token: %v", err))
}

authorizer, err := b.Authorizer(publicRoot)
if err != nil {
    panic(fmt.Errorf("failed to verify token and create authorizer: %v", err))
}

authorizerContents, err := parser.FromStringAuthorizerWithParams(`
	resource({res});
	operation({op});
	allow if right({res}, {op});
	`, map[string]biscuit.Term{"res": biscuit.String("/a/file1.txt"), "op": biscuit.String("read")})
if err != nil {
	panic(fmt.Errorf("failed to parse authorizer: %v", err))
}
authorizer.AddAuthorizer(authorizerContents)

if err := authorizer.Authorize(); err != nil {
    fmt.Printf("failed authorizing token: %v\n", err)
} else {
    fmt.Println("success authorizing token")
}
```

### Using biscuit-go grammar

biscuit-go provides a datalog parser, allowing to input datalog elements as plain strings, along with support for parameter substitution. 

See [GRAMMAR reference](./parser/GRAMMAR.md) for the complete syntax.

The parsers supports parsing whole blocks (containing several facts, rules and checks), whole authorizers (containing several facts, rules, checks and policies), as well as individual facts, rules, checks and policies. Parsing and adding elements individually is especially useful when doing so from inside a loop. 

The `parser` module provides convenient helpers for parsing a string into datalog elements (`FromStringFact`, `FromStringRule`, `FromStringCheck`, `FromStringPolicy`, `FromStringBlock`, `FromStringAuthorizer`, for static datalog snippets, and their counterparts allowing parameter substitution: `FromStringFactWithParams`, `FromStringRuleWithParams`, `FromStringCheckWithParams`, `FromStringPolicyWithParams`, `FromStringBlockWithParams`, `FromStringAuthorizerWithParams`).

#### Panic on parsing errors

In most cases, `FromString*` functions will let you handle errors. If you do not wish to handle errors and instead crash on errors (for instance in one-off scripts), it can be done by first creating a parser instance, and using the `panic`-y functions:

```go
p := parser.New()
b := biscuit.NewBuilder(privateRoot)

b.AddBlock(p.Must().Block(`
	right("/a/file1.txt", {read});
	right("/a/file1.txt", {write});
	right("/a/file2.txt", {read});
	right("/a/file3.txt", {write});
`, map[string]biscuit.Term{"read": biscuit.String("read"), "write": biscuit.String("write")}))

b.AddFact(p.Must().Fact(`resource({res})`, map[string]biscuit.Term{"res": biscuit.String("/a/file1.txt")}))
b.AddRule(p.Must().Rule(`
    can_read($file) 
        <- resource($file)
        $file.starts_with("/a/")
`, nil))
```

Do note that these helpers take two arguments: a datalog snippet and a parameters map. If the datalog snippet does not contain parameters, `nil` can be passed as the second argument.

## Examples

- [example_test.go](./example_test.go) for a simple use case
- [experiments folder](./experiments) for more advanced or specific use cases examples.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
