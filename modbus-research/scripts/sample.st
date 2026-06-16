PROGRAM basic_logic
  VAR
    test_register AT %MW0 : INT := 1234;
  END_VAR

  test_register := 1234;
END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms, PRIORITY := 0);
    PROGRAM instance0 WITH task0 : basic_logic;
  END_RESOURCE
END_CONFIGURATION
