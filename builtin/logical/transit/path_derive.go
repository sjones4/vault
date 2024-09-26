package transit

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const defaultKeyAgreementAlgorithm = "ecdh"

func (b *backend) pathDerive() *framework.Path {
	return &framework.Path{
		Pattern: "derive/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationVerb:   "derive",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},

			"public_key": {
				Type:        framework.TypeString,
				Description: "The pem-encoded ec public key",
			},

			"key_agreement_algorithm": {
				Type:    framework.TypeString,
				Default: defaultKeyAgreementAlgorithm,
				Description: `Key agreement algorithm to use. Valid values are:

* ecdh

Defaults to "ecdh".`,
			},

			"key_version": {
				Type: framework.TypeInt,
				Description: `The version of the key to use for derivation.
Must be 0 (for latest) or a value greater than or equal
to the min_encryption_version configured on the key.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathDeriveWrite,
		},

		HelpSynopsis:    pathDeriveHelpSyn,
		HelpDescription: pathDeriveHelpDesc,
	}
}

func (b *backend) pathDeriveWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	ver := d.Get("key_version").(int)
	keyAgreementAlgorithm := d.Get("key_agreement_algorithm").(string)
	if keyAgreementAlgorithm == "" {
		keyAgreementAlgorithm = defaultKeyAgreementAlgorithm
	}
	publicKeyPem := d.Get("public_key").(string)

	// Get the policy
	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	if !p.Type.SharedSecretDerivationSupported() {
		return logical.ErrorResponse("key type %v does not shared secret derivation", p.Type), logical.ErrInvalidRequest
	}

	if keyAgreementAlgorithm != defaultKeyAgreementAlgorithm {
		return logical.ErrorResponse("key agreement algorithm %s not supported for key type %v", keyAgreementAlgorithm, p.Type), logical.ErrInvalidRequest
	}

	if publicKeyPem == "" {
		return logical.ErrorResponse("public key not provided"), logical.ErrInvalidRequest
	}
	publicKey, err := parsePublicKey(publicKeyPem)
	if err != nil {
		return logical.ErrorResponse("public key invalid: %s", err.Error()), logical.ErrInvalidRequest
	}

	sharedSecret, err := p.DeriveSharedSecret(ver, &keysutil.SharedSecretDerivationOptions{
		KeyAgreementAlgorithm: keyAgreementAlgorithm,
		PublicKey:             publicKey,
	})
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		default:
			return logical.ErrorResponse(err.Error()), err
		}
	}

	resp := &logical.Response{}
	resp.Data = map[string]interface{}{
		"shared_secret": base64.StdEncoding.EncodeToString(sharedSecret),
	}

	return resp, nil
}

func parsePublicKey(publicKeyStr string) (any, error) {
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil {
		return nil, errors.New("could not decode PEM public key")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, errors.New("incorrect type for PEM public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

const pathDeriveHelpSyn = `Derive a shared secret for the given public key and
algorithm using a named key`

const pathDeriveHelpDesc = `
This path uses the named key from the request path to derive a shared secret
using the provided pem public key and key agreement algorithm.
`
