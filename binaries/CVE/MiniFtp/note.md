
MiniFtp v1.0

script:
```python
        if not self.binary_static:
            # self.state = self.project.factory.entry_state(remove_options={angr.options.LAZY_SOLVES})
            # arg1 = b"-c"
            arg2 = claripy.BVS('arg2', 2000 * 8)
            filename = b"miniftpd.conf"
            symbolic_file_size_bytes = 0x150
            prefix = b"max_per_ip="
            variable = claripy.BVS('filecontent', symbolic_file_size_bytes * 8)
            filecontent = claripy.BVV(prefix, len(prefix) * 8).concat(variable)
            # filecontent = claripy.BVS('filecontent', symbolic_file_size_bytes * 8)
            symfile = angr.storage.SimFile(filename, filecontent, has_end=False)
            self.state = self.project.factory.entry_state(
                add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                             angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
                remove_options={angr.options.LAZY_SOLVES,
                                angr.options.ALL_FILES_EXIST},
                args=[self.project.filename]
            )
            self.state.fs.insert(filename, symfile)
```
