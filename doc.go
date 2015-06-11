// Package authkit is a small library to provide a 3-legged oauth explicit flow
// for stateless rest services. You need a webapp for the user which communicates
// with a server backend. This backend uses authkit to talk to the oauth
// providers and generates a JWT token. All of the rest services can use
// authkit or any other JWT library to parse the token. When using clustered
// services you should distribute your private key to all of your services
// to check the JWT signature.
package authkit
