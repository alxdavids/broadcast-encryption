package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/cloudflare/bn256"
)

type CompletePublicKey struct {
	n int
	P bn256.G1
	PArr []bn256.G1
	Q bn256.G2
	QArr []bn256.G2
	V bn256.G1
}

func Setup(n int) (CompletePublicKey, []AdvertiserSecretKey, error) {
	r := rand.Reader
	_, P, err := bn256.RandomG1(r)
	if err != nil {
		return CompletePublicKey{}, nil, err
	}
	_, Q, err := bn256.RandomG2(r)
	if err != nil {
		return CompletePublicKey{}, nil, err
	}

	alpha, err := rand.Int(r, bn256.Order)
	if err != nil {
		return CompletePublicKey{}, nil, err
	}

	// build 2n-1 P_i values
	accumulatorP := new(bn256.G1).Set(P)
	var PArr []bn256.G1
	for i := 0; i < 2*n; i++ {
		accumulatorP = accumulatorP.ScalarMult(accumulatorP, alpha)
		if i != n {
			PArr = append(PArr, *new(bn256.G1).Set(accumulatorP))
		}
	}
	
	// build n Q_i values
	accumulatorQ := new(bn256.G2).Set(Q)
	QArr := make([]bn256.G2, n)
	for i := 0; i < n; i++ {
		accumulatorQ = accumulatorQ.ScalarMult(accumulatorQ, alpha)
		QArr[i] = *new(bn256.G2).Set(accumulatorQ)
	}

	// construct V
	gamma, err := rand.Int(r, bn256.Order)
	if err != nil {
		return CompletePublicKey{}, nil, err
	}
	V := new(bn256.G1).ScalarMult(P, gamma)

	// construct private keys
	privateKeys := make([]AdvertiserSecretKey, n)
	for i := 0; i < n; i++ {
		privateKeys[i] = AdvertiserSecretKey { 
			i: i,
			Di: *new(bn256.G1).ScalarMult(&PArr[i], gamma),
		}
	}

	return CompletePublicKey{
		n: n,
		P: *P,
		Q: *Q,
		PArr: PArr,
		QArr: QArr,
		V: *V,
	}, privateKeys, nil
}

func (cpk *CompletePublicKey) getPublicKey(i int) AdvertiserPublicKey {
	return AdvertiserPublicKey { n: cpk.n, Qi: cpk.QArr[i], PArr: cpk.PArr }
}

func (cpk *CompletePublicKey) broadcastPublicKey() BroadcastPublicKey {
	return BroadcastPublicKey { n: cpk.n, P: cpk.P, PArr: cpk.PArr, Q: cpk.Q, Q1: cpk.QArr[0], V: cpk.V }
}

type BroadcastPublicKey struct {
	n int
	P bn256.G1
	PArr []bn256.G1
	Q bn256.G2
	Q1 bn256.G2
	V bn256.G1
}

type Header struct {
	C0 *bn256.G2
	C1 *bn256.G1
}

func (bpk *BroadcastPublicKey) Encrypt(S []int) (Header, bn256.GT, error) {
	k, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return Header{}, bn256.GT{}, err
	}
	ele := bn256.Pair(&bpk.PArr[bpk.n-1], &bpk.Q1)
	K := ele.ScalarMult(ele, k)

	C1 := &bpk.V
	for _, j := range S {
		C1 = C1.Add(C1, &bpk.PArr[bpk.n - (j+1)])
	}
	C1 = C1.ScalarMult(C1, k)
	hdr := Header { 
		C0: new(bn256.G2).ScalarMult(&bpk.Q, k),
		C1: C1,
	}

	return hdr, *K, nil
}

type AdvertiserPublicKey struct {
	n int
	Qi bn256.G2
	PArr []bn256.G1
}

type AdvertiserSecretKey struct {
	i int
	Di bn256.G1
}

func (adsk *AdvertiserSecretKey) Decrypt(S []int, hdr Header, adpk AdvertiserPublicKey) *bn256.GT {
	numerator := bn256.Pair(hdr.C1, &adpk.Qi)
	val := &adsk.Di
	for _, j := range S {
		if j != adsk.i {
			val = val.Add(val, &adpk.PArr[adpk.n - (j+1) + (adsk.i+1)])
		}
	}
	denominator := new(bn256.GT).Neg(bn256.Pair(val, hdr.C0))
	out := new(bn256.GT).Add(numerator, denominator)
	return out
}

func main() {
	n := 1
	cpk, secretKeys, err := Setup(n)
	if err != nil {
		log.Fatalln(err)
	}

	S := []int{0}
	bpk := cpk.broadcastPublicKey()
	hdr, K, err := bpk.Encrypt(S)
	if err != nil {
		log.Fatalln(err)
	}

	chkK := secretKeys[0].Decrypt(S, hdr, cpk.getPublicKey(0)).Marshal()
	if string(K.Marshal()) != string(chkK) {
		fmt.Printf("Equality check failed\nK: %v\nchkK: %v", K.Marshal(), chkK)
	}
}