// This is a VERY broad Yara file, and due to the immense amount of rules needed to cover all languages, this is just a POC.
// Although this does not cover all languages, it can detect scripts in a broader sense (It may not identify the language but will detect that it is a script).

rule scripting_languages_detection
{
    meta:
        author = "Daryl Gatt"
        description = "Detects common scripting languages, focuses on common scripting languages."
        date = "2024-09-13"

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
        $python_lambda = "lambda "  // Python lambda expressions
        $python_self = "self"  // Used in class methods

        // Common file properties - C & C++
        $c_include = "#include " 
        $c_cpp_main = "int main("
        $cpp_namespace = "namespace " 
        $c_import = "#include <stdio.h>"
        $cpp_import = "#include <iostream>" 
        $cpp_string = "std::cout <<"
        $c_string = "printf("
        $c_return = "return 0;"  // Common in C/C++ to indicate successful completion

        // Common file properties - Ruby
        $ruby_require = "require "
        $ruby_module = "module "
        $ruby_end = "end"  // Marks the end of a block or method

        // Common file properties - Perl
        $perl_use = "use "  // For module imports in Perl
        $perl_strict = "use strict;"  // Perl strict mode

        // Common file properties - Haskell
        $haskell_main = "main = "  // Main function in Haskell

        // Common file properties - Go (Golang)
        $go_package = "package "  // Package declaration in Go
        $go_import = "import ("  // Import multiple packages in Go
        $go_main = "func main()"  // Main function in Go

        // Common Characteristics
        $python_and_ruby_function = "def "  // Shared function definition keyword

    condition:
        any of them
}

rule identify_script_file
{
    meta:
        author = "Daryl Gatt"
        description = "If the 'scripting_languages_detection' rule fails, will resort to this to see if the file is a script."
        date = "2024-09-13"

    strings:
        // Detect function definitions across various languages
        $function_definition_1 = "sub " nocase
        $function_definition_2 = "fn " nocase

        // Detect class definitions across various languages
        $class_definition = "class " nocase

        // Detect import or include statements
        $import_statement = "require " nocase

        // Detect comments in various scripting languages
        $code_comment_1 = "#" nocase
        $code_comment_2 = "//" nocase
        $code_comment_3 = "/*" nocase

        // Detect variable initialization across different languages
        $variable_initialization_1 = "let " nocase
        $variable_initialization_2 = "var " nocase
        $variable_initialization_3 = "const " nocase

        // Detect variable types in languages that use typing
        $variable_type_1 = "int " nocase
        $variable_type_2 = "float " nocase
        $variable_type_3 = "string " nocase
        $variable_type_4 = "bool " nocase
        $variable_type_5 = "char " nocase

        // Detect print statements across different languages
        $print_statement_1 = "printf(" nocase             // C, C++, PHP, Perl, Bash
        $print_statement_2 = "echo " nocase               // Bash, PHP, PowerShell
        $print_statement_3 = "print(" nocase              // Python, JavaScript, Ruby, Perl
        $print_statement_4 = "println(" nocase            // Java, Kotlin, Groovy, Scala
        $print_statement_5 = "Console.WriteLine(" nocase  // C#, .NET languages
        $print_statement_6 = "System.out.println(" nocase // Java
        $print_statement_7 = "document.write(" nocase     // JavaScript (DOM manipulation)
        $print_statement_9 = "write-host " nocase         // PowerShell
        $print_statement_10 = "cout <<" nocase            // C++
        $print_statement_11 = "fmt.Println(" nocase       // Go (Golang)
        $print_statement_12 = "Write-Output " nocase      // PowerShell

        // OOP Properties (Inheritance, Encapsulation, Polymorphism, Abstraction)
        $object_creation_1 = "self." nocase 
        
        // Detect inheritance across various languages
        $inheritance_1 = "extends " nocase
        $inheritance_2 = "implements " nocase
        
        // Detect access modifiers for encapsulation
        $access_modifier_1 = "public " nocase
        $access_modifier_2 = "private " nocase
        $access_modifier_3 = "protected " nocase
        
    condition:
        (
            any of (
                $function_definition_1,
                $function_definition_2,
                $class_definition,
                $import_statement,
                $code_comment_1,
                $code_comment_2,
                $code_comment_3,
                $variable_initialization_1,
                $variable_initialization_2,
                $variable_initialization_3,
                $variable_type_1,
                $variable_type_2,
                $variable_type_3,
                $variable_type_4,
                $variable_type_5,
                $print_statement_1,
                $print_statement_2,
                $print_statement_3,
                $print_statement_4,
                $print_statement_5,
                $print_statement_6,
                $print_statement_7,
                $print_statement_9,
                $print_statement_10,
                $print_statement_11,
                $print_statement_12
            )
        ) and
        (
            true or
            any of (
                $object_creation_1,
                $inheritance_1,
                $inheritance_2,
                $access_modifier_1,
                $access_modifier_2,
                $access_modifier_3
            )
        )
}
