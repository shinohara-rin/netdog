package netdog

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"

	"google.golang.org/protobuf/proto"
)

type NetDog struct {
	verbose         bool
	conn            *net.TCPConn
	transferBufsize int64
}

func New(verbose bool) (*NetDog, error) {
	return &NetDog{verbose: verbose, transferBufsize: 4096}, nil
}

func (dog *NetDog) ConnectToPeer(hostname string, port uint16) error {
	server := net.JoinHostPort(hostname, strconv.Itoa(int(port)))
	tcpAddr, err := net.ResolveTCPAddr("tcp", server)
	if err != nil {
		return err
	}
	dog.v("Connecting to " + server)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return err
	}
	dog.conn = conn
	return nil
}

func uniqueSliceElements[T comparable](inputSlice []T) []T {
	uniqueSlice := make([]T, 0, len(inputSlice))
	seen := make(map[T]bool, len(inputSlice))
	for _, element := range inputSlice {
		if !seen[element] {
			uniqueSlice = append(uniqueSlice, element)
			seen[element] = true
		}
	}
	return uniqueSlice
}

func (dog *NetDog) TransferFile(files []string) error {
	files = uniqueSliceElements(files)
	var headers GroupFileHeader
	for _, file := range files {
		fmt.Println("[+] Sending file " + file)
		fileHandle, err := os.Open(file)
		if err != nil {
			return err
		}
		defer fileHandle.Close()
		fileInfo, err := fileHandle.Stat()
		if err != nil {
			return err
		}
		fileSize := fileInfo.Size()
		fileName := fileInfo.Name()
		checksum, err := CalculateChecksum(fileHandle)
		if err != nil {
			return err
		}
		fmt.Printf("file: %s, size: %d, checksum: %s\n", fileName, fileSize, checksum)
		fileTransferInfo := FileHeader{
			Filename:     fileName,
			Filesize:     fileSize,
			Checksum:     checksum,
			ChecksumAlgo: "sha256sum",
		}
		headers.Files = append(headers.Files, &fileTransferInfo)
	}

	data, err := proto.Marshal(&headers)
	if err != nil {
		return err
	}
	dog.v("Sending file header")
	binary.Write(dog.conn, binary.BigEndian, uint32(len(data)))
	_, err = dog.conn.Write(data)
	if err != nil {
		return err
	}

	// wait for acception
	buf := make([]byte, 2)
	_, err = io.ReadFull(dog.conn, buf)
	if err != nil {
		return err
	}
	if string(buf) != "OK" {
		return errors.New("failed to receive OK from server")
	}

	// transfer file
	for _, file := range files {
		fileHandle, err := os.Open(file)
		if err != nil {
			return err
		}
		defer fileHandle.Close()
		_, err = io.Copy(dog.conn, fileHandle)
		if err != nil {
			return err
		}
	}
	return nil
}

func CalculateChecksum(file *os.File) (string, error) {
	hasher := sha256.New()
	buf := make([]byte, 1024)
	for {
		nbytes, err := file.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return hex.EncodeToString(hasher.Sum(nil)), nil
			} else {
				return "", err
			}
		}
		if nbytes == 0 {
			continue
		}
		n_written, err := hasher.Write(buf[:nbytes])
		if err != nil {
			return "", err
		}
		if n_written != nbytes {
			return "", fmt.Errorf("failed to write all bytes to hasher")
		}
	}
}

func (dog *NetDog) WaitForPeer(port uint16) {
	listen := fmt.Sprintf(":%d", port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		panic(err)
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		panic(err)
	}
	dog.v("Listening on " + listen)
	defer listener.Close()
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			panic(err)
		}
		dog.v("Connection from " + conn.RemoteAddr().String())
		go dog.HandlePeerConnection(conn)
	}
}

func (dog *NetDog) HandlePeerConnection(conn *net.TCPConn) {
	defer conn.Close()
	var messageBytes uint32
	binary.Read(conn, binary.BigEndian, &messageBytes)

	buf := make([]byte, messageBytes)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		log.Fatalln(conn.RemoteAddr(), err)
		return
	}
	dog.v("Received " + strconv.Itoa(int(messageBytes)) + " bytes from " + conn.RemoteAddr().String())

	var headers GroupFileHeader
	err = proto.Unmarshal(buf, &headers)
	if err != nil {
		log.Fatalln(conn.RemoteAddr(), err)
		return
	}

	for _, fileHeader := range headers.Files {
		fmt.Printf("Filename: %s\n", fileHeader.Filename)
		fmt.Printf("Filesize: %d\n", fileHeader.Filesize)
		fmt.Printf("Checksum: %s:%s\n", fileHeader.ChecksumAlgo, fileHeader.Checksum)
	}

	// begin transfer
	conn.Write([]byte("OK"))

	hasher := sha256.New()
	buf = make([]byte, dog.transferBufsize)
	// receive file
	for _, fileHeader := range headers.Files {
		// todo: what if the file name already exists?
		// and what if the filename is a path? i.e., a/b/c.txt
		fileHandle, err := os.Create(fileHeader.Filename)
		if err != nil {
			log.Fatalln(conn.RemoteAddr(), err)
			return
		}
		defer fileHandle.Close()

		n_chunks := int(fileHeader.Filesize / dog.transferBufsize)
		for i := 0; i < n_chunks; i++ {
			nbytes, err := io.ReadFull(conn, buf)
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				} else {
					log.Fatalln(conn.RemoteAddr(), err)
					return
				}
			}
			n_written, err := fileHandle.Write(buf)
			hasher.Write(buf)
			if err != nil {
				log.Fatalln(conn.RemoteAddr(), err)
				return
			}
			if n_written != nbytes {
				log.Fatalln(conn.RemoteAddr(), "failed to write all bytes to file")
				return
			}
		}

		// handle remaining bytes
		bytesToWrite := fileHeader.Filesize - int64(n_chunks)*dog.transferBufsize

		if bytesToWrite > 0 {
			remainingBuf := make([]byte, bytesToWrite)
			_, err := io.ReadFull(conn, remainingBuf)
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				} else {
					log.Fatalln(conn.RemoteAddr(), err)
					return
				}
			}

			n_written, err := fileHandle.Write(remainingBuf)
			hasher.Write(remainingBuf)
			if err != nil {
				log.Fatalln(conn.RemoteAddr(), err)
				return
			}
			if n_written != int(bytesToWrite) {
				log.Fatalln(conn.RemoteAddr(), "failed to write all bytes to file")
				return
			}
		}

		receivedChecksum := hex.EncodeToString(hasher.Sum(nil))
		if receivedChecksum != fileHeader.Checksum {
			log.Fatalln(conn.RemoteAddr(), "checksum mismatch for file ", fileHeader.Filename)
			return
		}
	}
}

func (dog *NetDog) v(msg string) {
	if dog.verbose {
		fmt.Println(msg)
	}
}
