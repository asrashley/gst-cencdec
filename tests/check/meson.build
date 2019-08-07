element_tests = ['aesctr/decrypt.c']

foreach test_file : element_tests
  test_name = test_file.split('.').get(0).underscorify()

  exe = executable(test_name, test_file,
    include_directories : [configinc],
    dependencies: [
      gst_dep, gst_base_dep,
      gst_check_dep, gst_cencdrm_dep,
    ],
  )

  test(test_name, exe, timeout: 3 * 60)
endforeach
