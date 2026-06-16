PROGRAM basic_logic
VAR
    counter AT %MW0 : INT := 0;
    led     AT %QX0.0 : BOOL := FALSE;
END_VAR

counter := counter + 1;

IF counter MOD 2 = 0 THEN
    led := TRUE;
ELSE
    led := FALSE;
END_IF;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#100ms,
               PRIORITY := 0);
    PROGRAM instance0
      WITH task0 : basic_logic;
  END_RESOURCE
END_CONFIGURATION