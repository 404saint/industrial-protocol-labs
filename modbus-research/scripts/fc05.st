PROGRAM basic_logic
VAR
    led AT %QX0.0 : BOOL := FALSE;
END_VAR


led := led; 

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#100ms,
               PRIORITY := 0);
    PROGRAM instance0
      WITH task0 : basic_logic;
  END_RESOURCE
END_CONFIGURATION
