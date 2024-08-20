

## IP module

The IP will be composed of three submodules: The traffic manager, the input manager, and the output manager. The communication between these modules are through queues which we respectively call 'in_pool' and 'out_pool':

    +-------------+  in_pool  +---------------+  out_pool  +--------------+
    | input mmngr | <-------- | traffic mngr. | <--------- | output mngr. |
    +-------------+           +-------+-------+            +--------------+
                                      | utun

* **traffic manager**: this unit is responsible for reading and writing IP packets from *utun*. This module will have minimal responsibilities, to make sure that input and output data is efficiently transmitted once ready.
* **input manager**: This unit is responsible for processing all the packets that are put into the in_pool.
* **output manager**: This unit is responsible for translating higher level input traffic into IP packets.