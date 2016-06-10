using System;
using System.IO;
using System.IO.Ports;
using System.IO.Pipes;
using System.Threading;

namespace wsbridge
{
    class Program
    {
        static NamedPipeServerStream wspipe; // for create pipe
        static BinaryWriter ws;   // for send data to pipe
        static SerialPort serialPort; // for send or receive data to serialPort
        const uint BUFSIZE = 100;
        static byte[] dataReceive = new byte[BUFSIZE];
        static byte length = 0;
        static FSM state;
        static long start_time_in_ticks;
        static String port;

        public struct CanCommand
        {
            public int ID;
            public byte lengthData;
            public byte[] data ;
            public int timeStamp;
            public bool haveTimeStamp;
        }

        enum FSM
        {
            START_CAPTURE,
            PACKET_CAPTURE,
            END_CAPTURE,
            SUCCESS
        }

        static void Main(string[] args)
        {
            ///////////// Commane line options  /////////////////////////
            if (args.Length == 0)
            {
               
                // generate list of active serial ports
                string[] names = SerialPort.GetPortNames();
                Console.WriteLine("Serial ports:");
                foreach (string name in names) Console.WriteLine(name);
                Console.Write("Choose one:"); // read name port (String)
                port = Console.ReadLine();
            }
            else if (args.Length == 1)
            {
                port = args[0];
            }
            else
            {
                Console.WriteLine("Usage: wsbridge <portname>");
                Console.WriteLine("or leave portname blank for a list of ports.");
                Environment.Exit(0);
            }


            
            ///////////////// Open serial port /////////////////////////
            try
            {
                serialPort = new SerialPort(port, 115200, Parity.None, 8, StopBits.One);
                serialPort.Open();
            }
            catch (Exception e)
            {
                // ooops, serial port can't be opened. throw exception, print message, and exit
                Console.WriteLine("Error opening serial port. Msg = " + e.Message);
                Environment.Exit(0);
            }
            Console.WriteLine("Serial port opened successfully.");



            ///////////////////// create pipe   /////////////////////////
            try
            {
                wspipe = new NamedPipeServerStream("wireshark", PipeDirection.Out);
            }
            catch (Exception e)
            {
                Console.WriteLine("Error opening pipe. Msg = " + e.Message);
                serialPort.Close();
                Environment.Exit(0);
            }
            

            ///////////// wait for wireshark to connect to pipe /////////////
            Console.WriteLine("Waiting for connection to wireshark.");
            Console.WriteLine("Open wireshark and connect to interface: Local:\\\\.\\pipe\\wireshark");
            wspipe.WaitForConnection();   // block process
            Console.WriteLine("Client connected.");


            //////////// connect binary writer to pipe to write binary data into it //////////
            ws = new BinaryWriter(wspipe);

            
            ///////////// add serial data capture event  ///////////////////////
           // serialPort.DataReceived += new SerialDataReceivedEventHandler(serialPort_DataReceived);
            state = FSM.START_CAPTURE; // set start state
            

            ///////////// keep track of time started. this will be used for timestamps ////////////
            start_time_in_ticks = DateTime.Now.Ticks; 


            //////////// generate header to identify the packet capture     ////////////////
            write_global_hdr();

            // run forever


            ///////////////////  initialize module  ///////////////////////////
            Console.WriteLine("Initialize Status:");

            closeCAN_Channel();
            
            setupCAN_BitRate('6');
            openCAN_Channel();

            //Thread.Sleep(milliseconds);

            //closeCAN_Channel();
            //closeCAN_Channel();
            //closeCAN_Channel();
            //closeCAN_Channel();
            //closeCAN_Channel();
          
            //closeCAN_Channel();
          //  setTimeStamp(true);




            while (true)
            {
                serialPort_DataReceived();
                switch (state)
                {

                    //  Read Data
                    case FSM.SUCCESS :
                        CanCommand CAN_Stuct = createStuctFromCommand();
                        write_frame((uint)CAN_Stuct.lengthData + 8, CAN_Stuct);

                        state = FSM.START_CAPTURE;
                        
                        break;
                }
            }
        }


        /* -------------------------------- initialize Functions ------------------------------------------*/

        static bool waitReceiveCommand()
        {
                while (serialPort.BytesToRead == 0) ;
                byte receiveByte = (byte)serialPort.ReadByte();
                Console.WriteLine(receiveByte);
                if (receiveByte == 13)  // CR (OK)
                {
                    
                    return true;
                }
                else    // BELL (ERROR)
                {
                    return false;
                }
        }

        static void setupCAN_BitRate(char mode)
        {
            byte[] command = { (byte)'S',(byte) mode, 13 };
            serialPort.Write(command, 0, 3);


            if ( waitReceiveCommand() )  // CR (OK)
            {
                Console.WriteLine("  -Setup bit-rate : OK");
            }
            else    // BELL (ERROR)
            {
                Console.WriteLine("  -Setup bit-rate : ERROR!!");
            }

        }

        static void openCAN_Channel()
        {
            byte[] command = { (byte)'O', 13 };
            serialPort.Write(command, 0, 2);

            if ( waitReceiveCommand() )  // CR (OK)
            {
                Console.WriteLine("  -Open CAN Channel: OK");
            }
            else    // BELL (ERROR)
            {
                Console.WriteLine("  -Open CAN Channel: ERROR!!");
            }
        }
        static void closeCAN_Channel()
        {
            //while (serialPort.BytesToRead != 0)
            //{
            //    byte receiveByte = (byte)serialPort.ReadByte();
            //    Console.WriteLine(receiveByte);
            //}

            byte[] command = { (byte)'C', 13 };
            serialPort.Write(command, 0, 2);

            if (waitReceiveCommand())  // CR (OK)
            {
                Console.WriteLine("  -Close CAN Channel: OK");
            }
            else    // BELL (ERROR)
            {
                Console.WriteLine("  -Close CAN Channel: ERROR!!");
            }
        }
        static void setTimeStamp(bool status)
        {
            byte[] command = { (byte)'Z', (byte)'0', 13 };

            if (status == false)
            {
                command[1] = (byte)'0';
            }
            else
            {
                command[1] = (byte)'1';
            }

            serialPort.Write(command, 0, 3);

            if (waitReceiveCommand())  // CR (OK)
            {
                Console.WriteLine("  -Setup timestamp: OK");
            }
            else    // BELL (ERROR)
            {
                Console.WriteLine("  -Setup timestamp: ERROR!!");
            }
        }

        static CanCommand createStuctFromCommand()
        {
            CanCommand tempCanCommand = new CanCommand();
            String commandStr = System.Text.Encoding.Default.GetString(dataReceive);
            String ID_str =""; 
            String[] data_str = new String[8];

            int EndID = 0 ;
            int lengthPosi = 0;
            int startData = 0;

             
            if ((char)dataReceive[0] == 't')
            {
                EndID = 3;
                lengthPosi = 4;
                startData = lengthPosi + 1;

            }
            else if ((char)dataReceive[0] == 'T')
            {
                EndID = 8;
                lengthPosi = 9;
                

            }

            startData = lengthPosi + 1;

            ID_str = commandStr.Substring(1, EndID ); // cut string for ID

            tempCanCommand.ID = Int32.Parse(ID_str, System.Globalization.NumberStyles.HexNumber); // ID
           // Console.WriteLine("ID_str " + ID_str + " ID_num " + tempCanCommand.ID);

            tempCanCommand.lengthData = (byte)(dataReceive[lengthPosi] - '0');// length

            byte[] dataTemp = new byte[tempCanCommand.lengthData];

            int j = startData;
            for (int i = 0; i < tempCanCommand.lengthData; i++)
            {
                data_str[i] += (char)dataReceive[j];
                data_str[i] += (char)dataReceive[j + 1];

                dataTemp[i] = (byte)Int32.Parse(data_str[i], System.Globalization.NumberStyles.HexNumber);
               // Console.WriteLine("data[" + i + "] " + data_str[i] + " dataTemp[i] " + dataTemp[i]);

                j += 2;
            }

            tempCanCommand.data = dataTemp;

           // Console.WriteLine("j : " + j +" length " + length);

            if (j < length - 1 ) // length include CR ( need -1 ) 
            {   
                String timeStr = commandStr.Substring(j, 4);

                tempCanCommand.haveTimeStamp = true;
                tempCanCommand.timeStamp = Int32.Parse(timeStr, System.Globalization.NumberStyles.HexNumber);
              //  Console.WriteLine("TimeStamp Str: " + timeStr + "TimeStamp int: " + tempCanCommand.timeStamp);
            }
            else
            {
                tempCanCommand.haveTimeStamp = false;
            }
       //     Console.WriteLine("");
        
            return tempCanCommand;


        }

        // serial port handler. this gets executed whenever data is available on the serial port
        //static void serialPort_DataReceived(object sender, System.IO.Ports.SerialDataReceivedEventArgs e)
        static void serialPort_DataReceived()
        {

                // loop until serial port buffer is empty
                if (serialPort.BytesToRead != 0)
                {                
                        byte input = 0;
                        if (state != FSM.SUCCESS)
                        {
                            input = (byte)serialPort.ReadByte();
                           // Console.WriteLine((char)input);
                        }

                       switch(state)
                       {
                           case FSM.START_CAPTURE :
                               if ( input == 't' || input == 'T' || input == 'r' || input == 'R' )
                               {
                                   state = FSM.PACKET_CAPTURE;
                                   dataReceive[0] = input;
                                   length = 1;
                               }

                               break;

                           case FSM.PACKET_CAPTURE :

                               dataReceive[length] = input;                              
                               length++;

                               if(input == 13){ // check CR
                                    state = FSM.SUCCESS ;
                                    //for (int i = 0; i < length; i++)
                                    //{
                                    //    Console.Write((char)dataReceive[i]);
                                    //}
                                    //Console.WriteLine("");

                               }
                               
                               break;

                            case FSM.SUCCESS :
                                     state = FSM.START_CAPTURE;
                               break;

                       }
                       
                    
                }
        
        }

       
        // this is the global header that starts any packet capture file. this will tell wireshark what 
        // kind of protocol it is (indicated by the DLT) as well as other information like endianness, etc.
        static void write_global_hdr()
        {
            uint magic_num = 0xa1b2c3d4;    // used for endianness
            short version_major = 2;        // version
            short version_minor = 4;        // version
            int thiszone = 0;               // zone (unused)
            uint sigfigs = 0;               // significant figures (unused)
            uint snaplen = 65535;           // snapshot length (max value)
            //uint snaplen = 20;           // snapshot length (max value)
            uint network = 227;             // Data Link Type (DLT): indicates link layer protocol

            try
            {
                // write to wireshark pipe
                ws.Write(magic_num);
                ws.Write(version_major);
                ws.Write(version_minor);
                ws.Write(thiszone);
                ws.Write(sigfigs);
                ws.Write(snaplen);
                ws.Write(network);
            }
            catch
            {
                Console.WriteLine("Pipe has been closed.");
                close();
            }
        }

        // this writes a frame header into wireshark in libpcap format. the format is simple and just
        // requires a timestamp and length
        static void write_frm_hdr(long sec, long usec, uint incl_len, uint orig_len)
        {
            try
            {
                // write to wireshark
                ws.Write((uint)sec);
                ws.Write((uint)usec);
                ws.Write(incl_len);
                ws.Write(orig_len);
            }
            catch
            {
                Console.WriteLine("Pipe has been closed.");
                close();
            }
       }

        // this writes a frame into wireshark. it calculates the timestamp and length and uses that 
        // for the frame header. it then writes captured bytes into wireshark       

        static void write_frame(uint frame_len, CanCommand CAN_Stuct)
        {
            uint incl_len, orig_len;
            long sec, usec;

            // generating timestamserialPort. its kind of cheesy but there isn't a unix timestamp mechanism in win. 
            // just counting ticks from when program was started. each tick is 100 nsec. 
            long diff_in_ticks = DateTime.Now.Ticks - start_time_in_ticks;  // get difference in ticks
            sec = diff_in_ticks / TimeSpan.TicksPerSecond;                  // get seconds
            diff_in_ticks -= (sec * TimeSpan.TicksPerSecond);               // subtract off seconds from total
            usec = diff_in_ticks / 10;                                      // get usec

            // calculate frame length. we won't be feeding frame checksum (FCS) into wireshark. 
            incl_len = (uint)frame_len;
            orig_len = frame_len;

            // write frame header first
            write_frm_hdr(sec, usec, incl_len, orig_len);

            
            
            // send CAN frame for wireshark
            ws.Write( (uint) littleToBigEndianInt32(CAN_Stuct.ID) );
            ws.Write( (byte) CAN_Stuct.lengthData);
            ws.Write((byte)0);//pad
            ws.Write((byte)0);//res0
            ws.Write((byte)0);//res1
            for (int i = 0; i < CAN_Stuct.lengthData ;i++ )
            {
                ws.Write( (byte) CAN_Stuct.data[i]);
            }
        }

        static UInt32 littleToBigEndianInt32(int number)
        {

            byte[] byteArray = BitConverter.GetBytes(number);
            Array.Reverse(byteArray);
            return BitConverter.ToUInt32(byteArray, 0);
        }


        // Received some type of termination. Close everything and wrap userialPort.
        static void close()
        {
            serialPort.Close();
            wspipe.Close();
            ws.Close();
            Console.WriteLine("Press <Enter> key to quit.");
            Console.ReadLine();
            Environment.Exit(0);
        }
    }
}
