#!/usr/bin/dmd -run

import std.stdio;
import std.mmfile;
import std.string;
import std.conv;

enum ELF_MAGIC = 0x464c457f;	/* \x7felf */

struct Elf 
{
	uint		e_magic;	// must equal ELF_MAGIC
	ubyte[12]	e_elf;
	ushort		e_type;
	ushort		e_machine;
	uint		e_version;
	uint		e_entry;
	uint		e_phoff;
	uint		e_shoff;
	uint		e_flags;
	ushort		e_ehsize;
	ushort		e_phentsize;
	ushort		e_phnum;
	ushort		e_shentsize;
	ushort		e_shnum;
	ushort		e_shstrndx;
}

struct Secthdr
{
	uint		sh_name;
	uint		sh_type;
	uint		sh_flags;
	uint		sh_addr;
	uint		sh_offset;
	uint		sh_size;
	uint		sh_link;
	uint		sh_info;
	uint		sh_addralign;
	uint		sh_entsize;
}

void main(string[] args)
{
	int i;
	string filename;
	string dumpSecName;
	Secthdr*[string] elfSections;
	
	enum Command {
		Nothing,
		ListSections,
		DumpSection
	}
	
	Command cmd = Command.Nothing;

	/* parse command line */
	try {
		for (i = 1; i < args.length; ++i) {
			switch (args[i])
			{
			case "--elf":
				filename = args[i + 1];
				++i;
				break;
			case "--list-sections":
				cmd = Command.ListSections;
				break;
			case "--dump-section":
				cmd = Command.DumpSection;
				dumpSecName = args[i + 1];
				++i;
				break;
			default:
				break;
			}
		}
	}
	catch (RangeError) {
		printUsage();
		return;
	}
	
	if ((filename.length == 0) || (cmd == Command.Nothing)) {
		printUsage();
		return;
	}



	auto fmap = new MmFile(filename);
	
	auto elf = cast(Elf*)fmap[0..Elf.sizeof];
	assert((elf.e_magic == ELF_MAGIC), "Bad or missing ELF magic number");
	
	/* acquire section names */
	auto sec = cast(Secthdr*)fmap[(elf.e_shoff + (elf.e_shstrndx * Secthdr.sizeof))..(elf.e_shoff + ((elf.e_shstrndx+1) * Secthdr.sizeof))];
	auto secNames = cast(char[])fmap[sec.sh_offset..(sec.sh_offset + sec.sh_size)];
	// printElfStringTable(secNames);
	
	/* traverse all sections building a data base */
	for (i = 0; i < elf.e_shnum; ++i) {
		// if (i == elf.e_shstrndx)
		// 	continue;

		sec = cast(Secthdr*)fmap[(elf.e_shoff + (i * Secthdr.sizeof))..(elf.e_shoff + ((i+1) * Secthdr.sizeof))];
		auto name = to!string(toStringz(secNames[sec.sh_name..$]));
		elfSections[name] = sec;
	}

	with (Command)
	switch (cmd)	
	{
	case ListSections:
		listSections(elfSections);
		break;
	case DumpSection:
		dumpSection(dumpSecName, elfSections, fmap);
		break;
	default:
		writeln("Command not yet supported");
		break;
	}
}

void printUsage()
{
	writeln("Options:");
	writeln("--elf <elf-filename>");
	writeln("--list-sections");
	writeln("--dump-section <section-name>");
}

void printElfStringTable(char[] stringBuff)
{
	foreach (c; stringBuff) {
		if (c != 0)
			write(c);
		else
			write("\n");
	}
}

void listSections(ref Secthdr*[string] elfSections)
{
	int i = 0;
	foreach (name, sec; elfSections) {
		writefln("[%2d] %s", i, name);
		++i;
	}
}

void dumpSection(string name, ref Secthdr*[string] elfSections, MmFile fmap)
{
	assert((name in elfSections), "non-existent section name");
	auto sec = elfSections[name];
	auto buff = cast(char[])fmap[sec.sh_offset..(sec.sh_offset + sec.sh_size)];
	write(buff);
}

