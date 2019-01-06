// rsao1.go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

/*
明文加密的分组操作
	.分组的长度 = 密钥的长度  //key = 64bit/8
	.将每组数据和密钥进行位运算
	.每组的密文长度 = 每组的明文长度
*/
/*
对称加密:
	1.des/3des/aes.NewCipher生成Cipher.NewCBC加/解密的数据模块
	2.使用Cipher.NewCBC进行加/解密
	3.对数据进行填充/删除
		1.填充:Cipher.NewCBC加密之前
		2.删除:Cipher.NewCBC解密之后
*/
func init() {
	fmt.Println("=== des 加解密 ===")
	scr := []byte("少壮不努力,活该你单身")
	key := []byte("12345678")

	src := encryptDES(scr, key)
	//fmt.Println("enpadding", src):每次运行加密后的数据一样
	des := decryptDES(src, key)
	fmt.Println("depadding", des)

	fmt.Println("=== 3des 加解密 ===")
	scr1 := []byte("少壮不努力,活该你单身,223333")
	key1 := []byte("aaabbbaa12345678ccddeeff")

	src1 := encryptTripleDES(scr1, key1)
	//fmt.Println("enpadding", src1):每次运行加密后的数据一样
	des1 := decryptTripleDES(src1, key1)
	fmt.Println("depadding", des1)

	fmt.Println("=== aes 加解密 ===")
	scra := []byte("少壮不努力,活该你单身,223333")
	keya := []byte("aaabbbaa12345678")

	srca := encryptAES(scra, keya)
	//fmt.Println("enpadding", srca):每次运行加密后的数据一样
	desa := decryptAES(srca, keya)
	fmt.Println("depadding", desa)

	//srcRsa := []byte("少壮不努力,活该你单身,334444")
	//GeneRsa(srcRsa,1024)
	//GeneRsa(4096)

	RsaTest()
}

func padding(src []byte, blockSize int) []byte {
	//func padding(src []byte, blockSize int) {
	//1.截取加密代码 段数
	fmt.Println("enpadding", src)
	padding := blockSize - len(src)%blockSize
	//2.有余数
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	//3.添加余数
	src = append(src, padText...)
	return src

}
func Depadding(src []byte) []byte {
	//1.取出最后一个元素
	lasteum := int(src[len(src)-1])
	//2.删除和最后一个元素相等长的字节
	//fmt.Println("src", src)
	newText := src[:len(src)-lasteum]
	return newText
}

//des加解密
//加密
func encryptDES(src, key []byte) []byte {
	//1.创建并返回一个使用DES算法的cipher.Block接口。
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//2.对src进行填充
	src = padding(src, block.BlockSize())
	//3.返回blockModel
	//vi := []byte("aaaabbbb")
	//blockModel := cipher.NewCBCEncrypter(block, vi)
	//fmt.Println("src[:block.BlockSize()]", key[:block.BlockSize()])
	blockModel := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	//4.crypto加密连续块
	blockModel.CryptBlocks(src, src)

	return src
}

//解密
func decryptDES(src, key []byte) []byte {
	//1.创建并返回一个使用DES算法的cipher.Block接口。
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//2.crypto解密
	//vi := []byte("aaaabbbb")
	//fmt.Println("src[:block.BlockSize()]", key[:block.BlockSize()])
	blockModel := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	//3.解密连续块
	blockModel.CryptBlocks(src, src)
	//.删除填充数组
	src = Depadding(src)

	return src
}

//3des加解密
//3des加密
func encryptTripleDES(src, key []byte) []byte {
	//1.创建并返回一个使用DES算法的cipher.Block接口。
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	//2.对src进行填充
	src = padding(src, block.BlockSize())
	//3.返回blockModel
	//vi := []byte("aaaabbbb")
	//blockModel := cipher.NewCBCEncrypter(block, vi)
	//fmt.Println("src[:block.BlockSize()]", key[:block.BlockSize()])
	blockModel := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	//4.crypto加密连续块
	blockModel.CryptBlocks(src, src)

	return src
}

/*
要求密钥长度:
	.16 ,24 ,32 byte
	.在go接口中指定的密钥长度为16字节
分组长度
	.16 ,24 ,32 byte
	.分组长度和密钥长度相等
*/
//3des解密
func decryptTripleDES(src, key []byte) []byte {
	//1.创建并返回一个使用DES算法的cipher.Block接口。
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	//2.crypto解密
	//vi := []byte("aaaabbbb")
	//fmt.Println("src[:block.BlockSize()]", key[:block.BlockSize()])
	blockModel := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	//3.解密连续块
	blockModel.CryptBlocks(src, src)
	//.删除填充数组
	src = Depadding(src)

	return src
}

//aes加解密
//aes加密
func encryptAES(src, key []byte) []byte {
	//1.创建并返回一个使用DES算法的cipher.Block接口。
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//2.对src进行填充
	src = padding(src, block.BlockSize())
	//3.返回blockModel
	//vi := []byte("aaaabbbb")
	//blockModel := cipher.NewCBCEncrypter(block, vi)
	//fmt.Println("key[:block.BlockSize()]", key[:block.BlockSize()])
	blockModel := cipher.NewCBCEncrypter(block, key[:block.BlockSize()]) //block.BlockSize() ==len(key)
	//4.crypto加密连续块
	blockModel.CryptBlocks(src, src)

	return src
}

//aes解密
func decryptAES(src, key []byte) []byte {
	//1.创建并返回一个使用DES算法的cipher.Block接口。
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//2.crypto解密
	//vi := []byte("aaaabbbb")
	//fmt.Println("src[:block.BlockSize()]", key[:block.BlockSize()])
	blockModel := cipher.NewCBCDecrypter(block, key[:block.BlockSize()]) //block.BlockSize() ==len(key)
	//3.解密连续块
	blockModel.CryptBlocks(src, src)
	//.删除填充数组
	src = Depadding(src)

	return src
}

func RsaTest() {
	//加密
	src := []byte("少壮不努力,活该你单身,223333")
	date, err := EnRsaPublic("PublicKey.pem", src)
	if err != nil {
		panic(err)
	}
	date, err = DeRsaPrivate(date, "PriveteKey.pem")
	if err != nil {
		panic(err)
	}
	fmt.Println("非对称加密解密结果", string(date))
}
