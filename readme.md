

## IP module

The IP will be composed of three submodules: The traffic manager, the input manager, and the output manager. The communication between these modules are through queues which we respectively call 'in_pool' and 'out_pool':

    +------------------+
    | reassembly store |
    +--------+---------+   
             |
      +------+------+  in_pool  +---------------+  out_pool  +--------------+
      | input mngr. | <-------- | traffic mngr. | <--------- | output mngr. |
      +-------------+           +-------+-------+            +--------------+
                                      | utun

* **traffic manager**: this unit is responsible for reading and writing IP packets from *utun*. This module will have minimal responsibilities, to make sure that input and output data is efficiently transmitted once ready.
* **input manager**: This unit is responsible for processing all the packets that are put into the in_pool.
* **output manager**: This unit is responsible for translating higher level input traffic into IP packets.


### Input manager

The input manager is responsible for re-assembling the IP fragments, and upon a whole message being ready, making it available for later processing. The *in_pool* is a fixed chunk of memory, to allow for fast access, and therefore ensure that no messages are lost.  
Thus, all packets awaiting further processing are first examined by the input manager, whether they need to be further processed (e.g. there are more fragments). 
* If **not**, they are passed on to the next step.
* If **yes**, they are going to be moved to the *reassembly store*.

## Reassembly store

The reassembly store is a linked list, with each link being a *Reassemble Entry*:

    typedef struct {
        re* next;           
        iphdr* hdr;                     // original packet header
        buf_id* id;                     // buffer id:
        char* data;                     // data
        char* bt;                       // bit table
        uint16_t tdl;                   // total data length
        unit8_t ttl;                    // time to live
        uint16_t tam;                   // total available memory
    } re;