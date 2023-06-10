unit VMProtectHardwareID;

interface


uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,  cpuid, System.Hash,
  System.Classes,System.NetEncoding,	Winapi.iphlpapi, Winapi.IpTypes ;

  type
  BlockType = (Cpu, Host, Mac, Hdd);
  TCPUID = array [1 .. 4] of Longint;
  TVendor = array [0 .. 11] of char;

    procedure AddBlock(const p: TArray<Byte>; const blockType: BlockType);
    procedure GetHdd();
    procedure GetMachineName();
    procedure GetCpu(method: Integer);
    function ToString(): string;
    procedure GetMacAddresses;
    function GetHardwareID(buf: integer=0): String;


  const
  OldMethodBlocks = 8;
  MaxBlocks = 16 + OldMethodBlocks;
  TypeMask = 3;
  ID_BIT = $200000; // EFLAGS ID bit
var
   _blocks: TArray<UInt32>;
   _startBlock: Integer=0;

implementation

function GetHardwareID(buf: integer=0): String;
begin
   // old methods
			GetCpu(0);
			GetCpu(1);
			_startBlock := Length(_blocks);
			
			GetCpu(2);
			GetMachineName();
			GetHdd();
			GetMacAddresses();
      if buf<>0 then
    	  Result:=Copy(ToString, 0, buf)
      else
        Result:= ToString;
end;


procedure GetHdd();
var
  driveLetter: string;
  serialNumber, maxComponentLength, fileSystemFlags: dword;
   getHddByte: TArray<Byte>;
begin
  driveLetter := ExtractFileDrive(GetEnvironmentVariable('SystemRoot')) + '\';
  if GetVolumeInformation(PChar(driveLetter), nil, 0, @serialNumber,
    maxComponentLength, fileSystemFlags, nil, 0) and (serialNumber <> 0) then
  begin
      SetLength(getHddByte, SizeOf(serialNumber));
     Move(serialNumber, getHddByte[0], Length(getHddByte));
      AddBlock(getHddByte, BlockType.Hdd);
  end;

end;

procedure GetMachineName();
var
  c1: dword;
  arrCh: array [0 .. MAX_PATH] of char;
  res: string;
   MachineNameByte: TArray<Byte> ;
begin
  c1 := MAX_PATH;
  GetComputerName(arrCh, c1);
  if c1 > 0 then
    res := arrCh
  else
    res := '';

    Res:=res.ToUpperInvariant;
    MachineNameByte:=  TEncoding.Unicode.GetBytes(res);
    AddBlock(MachineNameByte, BlockType.Host);
end;


function IsCPUID_Available: Boolean; register;
asm
  PUSHFD                                   { direct access to flags no possible, only via stack }
  POP     EAX                         { flags to EAX }
  MOV     EDX,EAX               { save current flags }
  XOR     EAX,ID_BIT     { not ID bit }
  PUSH    EAX                         { onto stack }
  POPFD                                        { from stack to flags, with not ID bit }
  PUSHFD                                   { back to stack }
  POP     EAX                         { get back to EAX }
  XOR     EAX,EDX               { check if ID bit affected }
  JZ      @exit                    { no, CPUID not availavle }
  MOV     AL,True               { Result=True }
@exit:
end;

function GetCPUID: TCPUID; assembler; register;
asm
  PUSH    EBX         { Save affected register }
  PUSH    EDI
  MOV     EDI,EAX     { @Resukt }
  MOV     EAX,1
  DW      $A20F       { CPUID Command }
  STOSD                         { CPUID[1] }
  MOV     EAX,EBX
  STOSD               { CPUID[2] }
  MOV     EAX,ECX
  STOSD               { CPUID[3] }
  MOV     EAX,EDX
  STOSD               { CPUID[4] }
  POP     EDI                         { Restore registers }
  POP     EBX
end;

function GetCPUVendor: TVendor; assembler; register;
asm
  PUSH    EBX                         { Save affected register }
  PUSH    EDI
  MOV     EDI,EAX               { @Result (TVendor) }
  MOV     EAX,0
  DW      $A20F                    { CPUID Command }
  MOV     EAX,EBX
  XCHG          EBX,ECX     { save ECX result }
  MOV               ECX,4
@1:
  STOSB
  SHR     EAX,8
  LOOP    @1
  MOV     EAX,EDX
  MOV               ECX,4
@2:
  STOSB
  SHR     EAX,8
  LOOP    @2
  MOV     EAX,EBX
  MOV               ECX,4
@3:
  STOSB
  SHR     EAX,8
  LOOP    @3
  POP     EDI                         { Restore registers }
  POP     EBX
end;

procedure __Init__;
begin

end;

procedure GetCpu(method: Integer);
var
  info: TArray<Int32>;
  infob: TArray<Byte>;
  CPUID: TCPUID;
  I: Integer;
  S: TVendor;
begin
  //TODO: foreach cpu:
     for I := Low(CPUID) to High(CPUID)  do CPUID[I] := -1;
  if IsCPUID_Available then begin
       CPUID:= GetCPUID;
  end;

  SetLength(info,Length(CPUID)) ;
   move( CPUID[1],info[0],sizeof(CPUID)) ;
  //info := ;
  if (info[0] and $FF0) = $FE0 then
    info[0] := info[0] xor $20; // fix Athlon bug
  info[1] := info[1] and $00FFFFFF; // mask out APIC Physical ID

  if method = 2 then begin
    info[2] := 0;
  end else if method = 1 then begin
    info[2] := info[2] and not (1 shl 27);
  end;

  SetLength(infob, 16);
  Move(info[0], infob[0], 16);
   AddBlock(infob, BlockType.Host);
end;

procedure AddBlock(const p: TArray<Byte>; const blockType: BlockType);
var
  hash: THashSHA1;
  h: TArray<Byte>;
  block, prevBlock: UInt32;
  i: Integer;
begin
  if Length(_blocks) = MaxBlocks then Exit; // no free space
  if Length(p) = 0 then Exit;

  hash := THashSHA1.Create;
  try
   hash.Update(p,0);
   h := hash.HashAsBytes;
    block := (h[0] shl 24) or (h[1] shl 16) or (h[2] shl 8) or h[3];
    block := block and not TypeMask; // zero two lower bits
    block := block or (Ord(blockType) and TypeMask); // set type bits

    // check existing blocks
    for i := Length(_blocks) downto (_startBlock + 1) do
    begin
      prevBlock := _blocks[i - 1];
      if prevBlock = block then Exit;
      if (prevBlock and TypeMask) <> (block and TypeMask) then Break;
    end;

    SetLength(_blocks, Length(_blocks) + 1);
    _blocks[Length(_blocks) - 1] := block;
  finally
  //  hash.Free;
  end;
end;

procedure ProcessMac(const p: TArray<Byte>);
var
  dw: Integer;
begin
  dw := (p[0] shl 16) or (p[1] shl 8) or p[2];
  if (dw = $000569) or (dw = $000C29) or (dw = $001C14) or (dw = $005056) or
     (dw = $0003FF) or (dw = $000D3A) or (dw = $00125A) or (dw = $00155D) or
     (dw = $0017FA) or (dw = $001DD8) or (dw = $002248) or (dw = $0025AE) or
     (dw = $0050F2) or (dw = $001C42) or (dw = $0021F6) then
    Exit;

  AddBlock(p, BlockType.Mac);
end;

procedure GetMacAddresses;
var
	pAdapterList, pAdapter: PIP_ADAPTER_INFO;
	BufLen, Status: DWORD;
	I,nextindex: Integer;
  ByteArray: TArray<Byte>;
begin
	BufLen := 1024 * 15;
	GetMem(pAdapterList, BufLen);
	try
		pAdapter := pAdapterList;
		while pAdapter <> nil do
		begin
			Status := GetAdaptersInfo(pAdapterList, BufLen);
			if (Status = 0) and (BufLen <> 0) then
			begin
				nextindex := pAdapter^.Index;
				if pAdapter^.Type_ = 6 then
				begin
					if pAdapter^.AddressLength > 0 then
					begin
 						SetLength(ByteArray, 6);
    				 Move(pAdapter^.Address, ByteArray[0], 6);
             ProcessMac(ByteArray);
					end;
					pAdapter := pAdapter^.next;
				end;
				if nextindex = pAdapter^.Index then			exit;
			end;
		end;
   Except
	 	FreeMem(pAdapterList);
	end;

end;

function GetBytes: TBytes;
var
  ms: TMemoryStream;
  i: Integer;
begin
  ms := TMemoryStream.Create;
  try
    for i := _startBlock to Length(_blocks) - 1 do
    begin
			ms.WriteData(_blocks[i], 4);
		end;
    SetLength(Result, ms.Size);
    ms.Position := 0;
    ms.Read(Result[0], Length(Result));
  finally
    ms.Free;
  end;
end;

function ToString: string;
var
  bytes: TBytes;
begin
  bytes := GetBytes;
  Result := TNetEncoding.Base64.EncodeBytesToString(bytes);
end;

end.
