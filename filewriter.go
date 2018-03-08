package main

import (
	"archive/tar"
	"compress/gzip"
	"io/ioutil"
	"os"
	"time"
)

type FileWriter interface {
	Mkdir(name string, perm os.FileMode) error
	WriteFile(filename string, data []byte, perm os.FileMode) error
	Close() error
}

type filesystem struct{}

var _ FileWriter = &filesystem{}

func NewFilesystem() (FileWriter, error) {
	return &filesystem{}, nil
}

func (filesystem) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(name, perm)
}

func (filesystem) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return ioutil.WriteFile(filename, data, perm)
}

func (filesystem) Close() error {
	return nil
}

type tgzfile struct {
	f   *os.File
	gz  *gzip.Writer
	tw  *tar.Writer
	now time.Time
}

var _ FileWriter = &tgzfile{}

func NewTGZFile(filename string) (FileWriter, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	gz := gzip.NewWriter(f)
	tw := &tgzfile{
		f:   f,
		gz:  gz,
		tw:  tar.NewWriter(gz),
		now: time.Now(),
	}

	return tw, nil
}

func (t *tgzfile) Mkdir(name string, perm os.FileMode) error {
	return t.tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     int64(perm),
		ModTime:  t.now,
		Typeflag: tar.TypeDir,
		Uname:    "root",
		Gname:    "root",
	})
}

func (t *tgzfile) WriteFile(filename string, data []byte, perm os.FileMode) error {
	err := t.tw.WriteHeader(&tar.Header{
		Name:     filename,
		Mode:     int64(perm),
		Size:     int64(len(data)),
		ModTime:  t.now,
		Typeflag: tar.TypeReg,
		Uname:    "root",
		Gname:    "root",
	})
	if err != nil {
		return err
	}

	_, err = t.tw.Write(data)
	return err
}

func (t *tgzfile) Close() error {
	err := t.tw.Close()
	if err != nil {
		return err
	}
	err = t.gz.Close()
	if err != nil {
		return err
	}
	return t.f.Close()
}
