package crash

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCrash(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Crash Suite")
}
