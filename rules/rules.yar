rule ExampleRule
{
    strings:
        $my_text_string = "test1"

    condition:
        $my_text_string
}
rule ExampleRule2
{
    strings:
        $my_text_string = "test2"

    condition:
        $my_text_string
}
