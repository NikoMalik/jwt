package jwt

import (
	"testing"
)

// go test -run ^TestMain$ -v

// var _p_ = newObjPool[[]byte](4, 64, func() []byte { return lowlevelfunctions.MakeNoZero(64) })

func TestMain(t *testing.T) {
	// test_ptr1 := _p_.get()
	//
	// t.Logf("test_ptr1 (allocated): %v", test_ptr1)
	// copy(test_ptr1, []byte{1, 2, 3, 4})
	// t.Logf("test_ptr1: %v", test_ptr1)
	//
	// _p_.put(test_ptr1)
	// t.Logf("test_ptr1: %v", test_ptr1)
	//
	// test_ptr2 := _p_.get()
	// t.Logf("test_ptr2 (allocated): %v", test_ptr2)
	// copy(test_ptr2, []byte{5, 6, 7, 8})
	// t.Logf("test_ptr2: %v", test_ptr2)
	//
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

// A sample allocator function for testing
func intAllocator() int {
	return 42 // Arbitrary value to return from the pool
}

// // Test objectPool initialization
// func TestObjectPoolInitialization(t *testing.T) {
// 	pool := newObjPool(12, 4, intAllocator)
//
// 	// Test initial capacity and chunk size
// 	if len(pool.obj) != 12 {
// 		t.Errorf("Expected pool to have 12 chunks, but got %d", len(pool.obj))
// 	}
//
// 	if pool.chunkSize != 4 {
// 		t.Errorf("Expected chunk size to be 4, but got %d", pool.chunkSize)
// 	}
//
// 	fmt.Println(len(pool.obj[0]))
// 	fmt.Println(len(pool.freeptr))
//
// 	p := pool.get()
// 	fmt.Println(len(pool.freeptr))
// 	pool.put(p)
// 	fmt.Println(len(pool.freeptr))
// }
//
// // Test object allocation and deallocation from the pool
// func TestObjectPoolGetPut(t *testing.T) {
// 	pool := newObjPool(10, 4, intAllocator)
//
// 	// Test that an object can be obtained from the pool
// 	obj1 := pool.get()
// 	if obj1 != 42 {
// 		t.Errorf("Expected object value to be 42, but got %d", obj1)
// 	}
//
// 	// Test that an object can be returned to the pool
// 	pool.put(obj1)
//
// 	// Test that the object is reused when requested again
// 	obj2 := pool.get()
// 	if obj2 != 42 {
// 		t.Errorf("Expected object value to be 42, but got %d", obj2)
// 	}
//
// 	// Check that we are reusing the same object (the pool is working)
// 	if obj1 != obj2 {
// 		t.Errorf("Expected object to be reused, but got different instances")
// 	}
// }
