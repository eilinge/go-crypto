// MyRas.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	//"fmt"
	"os"
)

func main() {
	//加密
	GeneRsa(1024)
	/*
		src := []byte("少壮不努力,活该你单身,223333")
		date, err := EnRsaPublic("PublicKey.pem", src)
		fmt.Println("非对称加密解密数据", string(src))
		if err != nil {
			panic(err)
		}
		date, err = DeRsaPrivate(date, "PriveteKey.pem")
		if err != nil {
			//当函数F调用panic时，F的正常执行就会立刻停止
			panic(err)
		}
		fmt.Println("非对称加密解密结果", string(date))

		src1 := []byte("少壮不努力,活该你单身122333")
		fmt.Println("Rsa加密数据:", string(src1))
		newsrc, _ := EnRsaPublickey(src, "PublicKey.pem")
		//fmt.Println(newsrc)
		orginsrc, _ := DeRsaPrivtekey(newsrc, "PrivateKey.pem")
		fmt.Println("Rsa解密数据:", string(orginsrc))
	*/
}
/*
非对称加密:
	1.生成公/私钥文件
		1.rsa:生成公/私钥
		2.x509:对公/私钥编码
			1.私钥:ASN.1 PKCS#1 DER编码。
			2.公钥:PKIX格式DER编码
		3.pem:使用pem进行公/私钥的加/解密并存储成.pem文件
	2.公钥加密/私钥解密
*/
/*
pem: 	实现了PEM数据编码;主要用于TLS密钥和证书
x509: 	x509包解析X.509编码的证书和密钥。
	x509.MarshalPKCS1PrivateKey(PrivateKey)	:将rsa私钥序列化为ASN.1 PKCS#1 DER编码。
	x509.MarshalPKIXPublicKey(&PublicKey)	:将公钥序列化为PKIX格式DER编码
	x509.ParsePKIXPublicKey(block.Bytes)	:解析一个DER编码的公钥。这些公钥一般在以"BEGIN PUBLIC KEY"出现的PEM块中
	x509.ParsePKCS1PrivateKey(block.Bytes)	:解析ASN.1 PKCS#1 DER编码的rsa私钥
rsa: 	实现了PKCS#1规定的RSA加密算法。
	rsa.GenerateKey	使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	rsa.EncryptPKCS1v15(rand.Reader, pubkey, src)
	rsa.DecryptPKCS1v15(rand.Reader, pubkey, src)

PKCS#1：定义RSA公开密钥算法加密和签名机制，主要用于组织PKCS#7中所描述的数字签名和数字信封[22]。
PKCS#3：定义Diffie-Hellman密钥交换协议。
PKCS#6：描述了公钥证书的标准语法，主要描述X.509证书的扩展格式。
PKCS#7：定义一种通用的消息语法，包括数字签名和加密等用于增强的加密机制，PKCS#7与PEM兼容;
PKCS#13：椭圆曲线密码体制标准。
PKCS#15：密码令牌信息格式标准。
*/
/*
生成私钥操作流程
	1.使用rsa中GenerateKey方法生成私钥
	2.通过x509标准将得到的rsa私钥序列化为ASN.1的DER编码字符串
	3.将私钥字符串设置到pem格式块中
	4.通过pem将设置好的数据进行编码,并写入磁盘文件中
生成公钥操作流程
	1.从得到的私钥对象中将公钥信息取出
	2.通过x509标准将得到的rsa公钥序列化为ASN.1的DER编码字符串
	3.将公钥字符串设置到pem格式块中
	4.通过pem将设置好的数据进行编码,并写入磁盘文件中
*/

func GeneRsa(blockSize int) error {
	PrivateKey, err := rsa.GenerateKey(rand.Reader, blockSize)
	if err != nil {
		return err
	}

	stream := x509.MarshalPKCS1PrivateKey(PrivateKey)

	block := pem.Block{
		Type:  "RSA PrivateKey",
		Bytes: stream,
	}
	PrivateFile, err := os.Create("PrivateKey.pem")
	if err != nil {
		return err
	}

	err = pem.Encode(PrivateFile, &block)

	PublicKey := PrivateKey.PublicKey

	stream1, err := x509.MarshalPKIXPublicKey(&PublicKey)
	if err != nil {
		return err
	}

	block1 := pem.Block{
		Type:  "RSA PublicKey",
		Bytes: stream1,
	}
	PublicFile, err := os.Create("PublicKey.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(PublicFile, &block1)
	return err
}

/*
公钥加密
	1.将公钥取出得到PEM编码的字符串
	2.将得到的字符串进行pem解码
	3.使用x509进行解析公钥
	4.使用Rsa对公钥进行加密
私钥解密
	1.将私钥取出得到PEM编码的字符串
	2.将得到的字符串进行pem解码
	3.使用x509进行解析私钥
	4.对私钥使用rsa进行解密
*/
func EnRsaPublickey(src []byte, fileName string) ([]byte, error) {
	msg := []byte(" ")
	file, err := os.Open(fileName)
	if err != nil {
		return msg, err
	}
	info, err := file.Stat()
	if err != nil {
		return msg, err
	}
	fileSize := info.Size()
	newPem := make([]byte, fileSize)
	file.Read(newPem)

	block, _ := pem.Decode(newPem)
	pubkey1, _ := x509.ParsePKIXPublicKey(block.Bytes)

	pubkey := pubkey1.(*rsa.PublicKey)
	msg, err = rsa.EncryptPKCS1v15(rand.Reader, pubkey, src)
	if err != nil {
		return msg, err
	}
	return msg, err
}

func DeRsaPrivtekey(src []byte, fileName string) ([]byte, error) {
	msg := []byte(" ")
	file, err := os.Open(fileName)
	if err != nil {
		return msg, err
	}
	info, err := file.Stat()
	if err != nil {
		return msg, err
	}
	fileSize := info.Size()
	newPem := make([]byte, fileSize)
	file.Read(newPem)

	block, _ := pem.Decode(newPem)
	pubkey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	//pubkey := pubkey1.(*rsa.PublicKey)
	msg, err = rsa.DecryptPKCS1v15(rand.Reader, pubkey, src)
	fmt.Println("msg", msg)
	if err != nil {
		return msg, err
	}
	return msg, err
}
