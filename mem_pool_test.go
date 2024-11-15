package jwt

import (
	"testing"

	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
)

// go test -run ^TestMain$ -v

type Dataobj struct {
	data [256]byte
}

var _p_ = newObjPool[[]byte](4, func() []byte { return lowlevelfunctions.MakeNoZero(64) })

func TestMain(t *testing.T) {
	test_ptr1 := _p_.get()

	t.Logf("test_ptr1 (allocated): %v", test_ptr1)
	copy(test_ptr1, []byte{1, 2, 3, 4})
	t.Logf("test_ptr1: %v", test_ptr1)

	_p_.put(test_ptr1)
	t.Logf("test_ptr1: %v", test_ptr1)

	test_ptr2 := _p_.get()
	t.Logf("test_ptr2 (allocated): %v", test_ptr2)
	copy(test_ptr2, []byte{5, 6, 7, 8})
	t.Logf("test_ptr2: %v", test_ptr2)

	// var pool1 Pool[[]byte]
	//
	// // Initialize memory pool
	// PoolInitialize(&pool1, 4, 8, func() []byte { return make([]byte, 4) })
	//
	// // Allocate memory
	// test_ptr1 := PoolMalloc(&pool1)
	// test_ptr2 := PoolMalloc(&pool1)
	//
	// // Assign values for clarity
	// copy(test_ptr1, []byte{1, 2, 3, 4})
	// copy(test_ptr2, []byte{5, 6, 7, 8})
	//
	// t.Logf("test_ptr1 (allocated): %v, test_ptr2 (allocated): %v", test_ptr1, test_ptr2)
	//
	// // Free memory
	// PoolFree(&pool1, &test_ptr1)
	// t.Logf("test_ptr1 (freed): %v, test_ptr2 (still allocated): %v", test_ptr1, test_ptr2)
	//
	// // Free memory
	// PoolFree(&pool1, &test_ptr2)
	// t.Logf("test_ptr1 (freed): %v, test_ptr2 (freed): %v", test_ptr1, test_ptr2)
	//

	// t.Logf("publickey2: %v", publickey2)
	// copy(publickey2, []byte{5, 6, 7, 8})
	// t.Logf("publickey2: %v", publickey2)
	// // _ = publickey2[:0]
	// // t.Logf("publickey2: %v", publickey2)
	// _p_.put(&publickey2)
	// //
	// // publickey3 := _p_.get()
	// // t.Logf("publickey3: %v", publickey3)
	// copy(publickey3, []byte{9, 10, 11, 12})
	// t.Logf("publickey3: %v", publickey3)
	//
	// _p_.put(&publickey3)
	// // t.Logf("publickey2: %v", publickey2)
	// //
} //
