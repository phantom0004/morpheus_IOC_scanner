// Due to the immense amount of rules needed to cover all languages, this is just a demonstration.
rule simple_scripting_languages_detection
{
    meta:
        author = "Daryl Gatt"
        description = "Detects common scripting languages, focuses on common scripting languages."
        date = "2024-09-23"

    strings:
        // Common Shebangs
        $python_bin_shebang = "#!/usr/bin/python" nocase 
        $python_env_shebang = "#!/usr/bin/env python" nocase
        $bash_shebang = "#!/bin/bash" nocase
        $perl_shebang = "#!/usr/bin/perl" nocase
        $lua_shebang = "#!/usr/bin/lua" nocase

        // Common file properties - Python
        $python_import = "import " 
        $python_exception = "except"
        $python_main = "def main():"

        // Common file properties - C & C++
        $c_include = "#include " 
        $c_cpp_main = "int main("
        $cpp_namespace = "namespace " 
        $c_import = "#include <stdio.h>"
        $cpp_import = "#include <iostream>" 
        $cpp_string = "std::cout <<"
        $c_string = "printf("

        // Common file properties - Ruby
        $ruby_import = "require "

        // Common file properties - Go (Golang)
        $go_package = "package "  // Package declaration in Go
        $go_import = "import ("  // Import multiple packages in Go
        $go_main = "func main()"  // Main function in Go

    condition:
        any of them
}
