# @presswink/firebase-jwt
this package is going to verify firebase access-token without using firebase admin sdk.

## Getting Start

1) install the package

`NPM`

```cmd
npm i @presswink/firebase-jwt
```

`yarn`

```cmd
yarn add @presswink/firebase-jwt
```

2) Examples

`typescript` or `es6`

```ts
import FirebaseJwt from '@presswink/firebase-jwt'

const projectId: string = "firebase-auth"
const jwtToken: string  = ""

const jwt = new FirebaseJwt(projectId)

// verify jwt tokens

const verifyResult = jwt.verify(jwtToken)
console.log(verifyResult)

// decode jwt tokens
const decodeResult = jwt.decode(jwtToken)
console.log(decodeResult)

```


`commonjs`

```js
const FirebaseJwt = require('@presswink/firebase-jwt')

const projectId = "firebase-auth"
const jwtToken = ""

const jwt = new FirebaseJwt(projectId)

// verify jwt tokens

const verifyResult = jwt.verify(jwtToken)
console.log(verifyResult)

// decode jwt tokens
const decodeResult = jwt.decode(jwtToken)
console.log(decodeResult)

```


`next.js`

```js
'use server'

const {NextFirebaseJwt} = require('@presswink/firebase-jwt')

const projectId = "firebase-auth"
const jwtToken = ""

const jwt = new NextFirebaseJwt(projectId)

// verify jwt tokens

const verifyResult = jwt.verify(jwtToken)
console.log(verifyResult)

// decode jwt tokens
const decodeResult = jwt.decode(jwtToken)
console.log(decodeResult)

```


# Development Guide

1) clone the repository
```cmd
git clone https://github.com/presswink/firebase-jwt.git
```

2) node version should be >= `v22.4.0`

3) install packages

`NPM`
```cmd
npm i
```

`yarn`
```cmd
yarn install
```



5) build project

`NPM`
```cmd
npm run build
```

`yarn`
```cmd
yarn build
```


4) run the test cases

`NPM`
```cmd
npm run test
```

`yarn`
```cmd
yarn test
```



# Docs

### [changelog.md](changelog.md)



# Contributor

[@Aditya panther](https://github.com/Adityapanther)

