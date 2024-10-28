# r2_beta_15h50_decrypter
Decrypter for [newly-discovered Rayman 2 Beta Demo](https://raymanpc.com/forum/viewtopic.php?p=1490992#p1490992) `MaiCFXvr.exe`

It appears that Ubi Soft were really paranoid about people reverse-engineering this demo when it was released in 1998, because they made it practically impossible to disassemble, like so:

* They swapped the names of the `.text` and `.data` sections.
* They encrypted the `.text` and `.data` sections, as well as the `.idata` section containing imports.
* The decryption is handled in a special `.udata` section, which is also encrypted, using a slightly different algorithm!
* The main decryption routine in `.udata` is encrypted _instruction-by-instruction_! I'm not kidding folks, _every single assembly instruction_ is encrypted individually, and the decryption routine gets called every single time to fetch the next one!
* The `.udata` section contains a home-made parser for the import data, since it can only be processed after `.idata` is decrypted. Unlike Windows' normal EXE loader, this one doesn't stop on failure, resulting in really weird crashes if you have a missing/incompatible DLL!

This tool basically does what the `.udata` code does, but offline, and produces an output file that you can disassemble or run without issues.

# Usage

If you want to compile it yourself:
```
$ git clone https://github.com/PluMGMK/r2_beta_15h50_decrypter.git
$ cd r2_beta_15h50_decrypter
$ cargo run --release -- /path/to/MaiCFXvr.exe
```
This will then create `/path/to/MaiCFXvr.exe.decrypted.exe`, which you can disassemble or run as a normal Windows EXE file.

Otherwise, you can download the pre-compiled r2_beta_15h50_decrypter.exe from the releases page and run it. On Windows, you can just drag a MaiCFXvr.exe onto it in the GUI!
