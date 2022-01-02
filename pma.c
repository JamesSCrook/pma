/*******************************************************************************
********************************************************************************

    pma: reads input text files and transforms them into a format that is
    suitable for analysis - particularly graphical analysis.
    
    Copyright (C) 2016-2022 James S. Crook

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

********************************************************************************
*******************************************************************************/

/*******************************************************************************
pma: (Performance Monitor Analyzer) - this C program - reads input text files in
the same format produced by pmc (see below) and transforms the data into
formats that are useful for graphical analysis.

pmc: (Performance Monitor Collector) is a Linux/UNIX shell script that produces
text system performance output in a particular text format.

pma can transform any correctly formatted data (not just Linux/Unix performance
data), irrespective of what kind. See the README file for more information.
*******************************************************************************/

#define PROGVERSIONSTR	"0.0.2"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <locale.h>
#include <sys/stat.h>

#define QUOTECHAR	'\''
#define COMMENTCHAR	'#'
#define STANZATERMCHAR	':'
#define NODEVICENAME	"None"
#define STDINFILENAME	"-"

#define TIMEVALUES	"TIME_VALUES:"
#define COUNTIDX	0
#define INTERVALIDX	1
#define NUMTIMEVALUES	2	/* Only comments after that */

#define METADATASTR	"METADATA:"
#define CLASSSTRIDX	0
#define CLASSTYPEIDX	1
#define STARTROWIDX	2
#define NUMMETAITEMS	3
#define MAXNUMMETRICS	32
#define MAXNUMMETADATA	(NUMMETAITEMS+MAXNUMMETRICS)
#define ARRAYCLASS	'A'
#define VECTORCLASS	'V'

#define MAXCLSNAMELEN	32
#define MAXMETNAMELEN	32
#define MAXDEVNAMELEN	32
#define MAXDATSTZLEN	32
#define MAXFORMATSTRLEN	64
#define MAXMETDEVNAMELEN (MAXMETNAMELEN+MAXDEVNAMELEN+32)

#define DATESTR		"DATE:"
#define TIMESTAMPIDX	0
#define NUMDATEARGS	1	/* Only comments after that */

#define MAXTMSTPSTRLEN	128
#define MAXINPUTLINELEN	256
#define MAXPARAMVALLEN	128
#define MAXPATHNAMELEN	2048
#define MULTIDIRMODE	0755

/* Macros */
#define WHITESPACE(c)   (((c)==' '||(c)=='\t'||(c)=='\n') ? 1 : 0) 
#define MIN(a,b)	((a)<(b)?(a):(b))
#define MAX(a,b)	((a)>(b)?(a):(b))

typedef struct {			/* e.g., sda, eth0 or NA */
    char	devicename[MAXDEVNAMELEN+1];
    int		number;
    double	max;
    double	sum;
    double	scale;
    double	*valuetbl;		/* there should always be count entries! */
    FILE	*fileptr;
} Device;

typedef struct {			/* e.g., cpu_us and tps */
    char	metricname[MAXMETNAMELEN+1];
    int		number;
    double	max;
    double	sum;
    int		numdevices;
    Device	*devicetbl;
} Metric;

typedef struct {			/* e.g., IO, VM, NET */
    char	classname[MAXCLSNAMELEN+1];
    char	classtype;
    int		startrow;
    int		nummetrics;
    Metric	*metrictbl;
} Class;

/*********** uninitialized global variables ***********/
FILE		*inputfileptr;
FILE		*clockticksfileptr;
int		numclasses;
int		count;
int		interval;
unsigned	inputlinectr;
double		fullscale;

/*********** initialized global variables ***********/
int		verbosity		= 0;
int		datavaluesflag		= 0;
int		parametersflag		= 0;
time_t		firsttimestamp		= 0;
char		*configfilename 	= NULL;
Class		*classtbl		= NULL;

/*******************************************************************************
Define the configuration parameter table and populate it with default values (of
the various types) for each parameter.
*******************************************************************************/
#define CHAR	0
#define FLTPNT	1
#define INTEGER	2
#define STRING	3

typedef union {
    char	character;
    double	fltpnt;
    long int	longint;
    char	*string;
} Paramtype;

typedef struct {
    int		idx;
    char	*paramname;
    int		type;
    Paramtype	defaultvalue;
    Paramtype	value;
} Param;

/* IDXs must start at 0, increase by 1, and be in the same order as in paramtbl! */
#define FULLSCALEIDX		 0
#define TIMEZONEIDX		 1
#define METDEVSEPARATORIDX	 2
#define SINGFILEDATEFMTIDX	 3
#define SINGFILEDELIMITERIDX	 4
#define MULTIFILEDATEFMTIDX	 5
#define MULTIFILEDELIMITERIDX	 6
#define MULTIFILEHEADERFMTIDX	 7
#define CLOCKTICKSFILENAMEIDX	 8
#define CLOCKTICKSLEV0IDX	 9
#define CLOCKTICKSLEV1IDX	10
#define CLOCKTICKSLEV2IDX	11
#define CLOCKTICKSLEV3IDX	12
#define CLOCKTICKSLEV4IDX	13
#define CLOCKTICKSLEV5IDX	14
#define CLOCKTICKSLEV6IDX	15
#define CLOCKTICKSLEV7IDX	16
#define NUMCLOCKTICKSLEVELS	8
Param paramtbl[] = {
    {FULLSCALEIDX,          "fullscale",             FLTPNT,  {.fltpnt   =100.0        }, {.string=""}},
    {TIMEZONEIDX,           "TZ",                    STRING,  {.string   =""           }, {.string=""}},
    {METDEVSEPARATORIDX,    "metricdeviceseparator", STRING,  {.string   ="_"          }, {.string=""}},
    {SINGFILEDATEFMTIDX,    "singlefiledateformat",  STRING,  {.string   ="%x %X"      }, {.string=""}},
    {SINGFILEDELIMITERIDX,  "singlefiledelimiter",   CHAR,    {.character=','          }, {.string=""}},
    {MULTIFILEDATEFMTIDX,   "multifiledateformat",   STRING,  {.string   ="%s"         }, {.string=""}},
    {MULTIFILEDELIMITERIDX, "multifiledelimiter",    CHAR,    {.character=' '          }, {.string=""}},
    {MULTIFILEHEADERFMTIDX, "multifileheaderformat", STRING,  {.string   ="\"%s|%.1f\""}, {.string=""}},
    {CLOCKTICKSFILENAMEIDX, "clockticksfilename",    STRING,  {.string   ="clockticks" }, {.string=""}},
    {CLOCKTICKSLEV0IDX,     "clockticks_level_0",    INTEGER, {.longint  =24*60*60     }, {.string=""}},
    {CLOCKTICKSLEV1IDX,     "clockticks_level_1",    INTEGER, {.longint  =12*60*60     }, {.string=""}},
    {CLOCKTICKSLEV2IDX,     "clockticks_level_2",    INTEGER, {.longint  = 6*60*60     }, {.string=""}},
    {CLOCKTICKSLEV3IDX,     "clockticks_level_3",    INTEGER, {.longint  =   60*60     }, {.string=""}},
    {CLOCKTICKSLEV4IDX,     "clockticks_level_4",    INTEGER, {.longint  =   30*60     }, {.string=""}},
    {CLOCKTICKSLEV5IDX,     "clockticks_level_5",    INTEGER, {.longint  =   15*60     }, {.string=""}},
    {CLOCKTICKSLEV6IDX,     "clockticks_level_6",    INTEGER, {.longint  =    5*60     }, {.string=""}},
    {CLOCKTICKSLEV7IDX,     "clockticks_level_7",    INTEGER, {.longint  =       0     }, {.string=""}},
};
#define NUMCONFIGPARAMS	(sizeof(paramtbl)/sizeof(Param))

typedef struct {
    char *shortform;
    char *longform;
    int  minuniqlen;
} Optiontype;

#define USAGEMSGFMT "usage (v %s):\n\
%s [OPTION ...] inputfile ...\n\
    Where the OPTIONs are:\n\
	-c|--configurationfile	configuration_file_name\n\
	-s|--singlefile		single_output_file_name\n\
	-m|--multifiledirectory	multiple_files_directory_name\n\
	-d|--datavalues\n\
	-p|--parameters\n\
	-v|--verbose\n\
	-h|--help\n"

/*******************************************************************************
Display the usage message.
*******************************************************************************/
void display_usage_message(char *prog)
{
    fprintf(stderr, USAGEMSGFMT, PROGVERSIONSTR, prog);
}


/*******************************************************************************
Called after a system call error to display details and then exit. May be called
with one or more arguments.
*******************************************************************************/
void err_exit(const char *formatstr, ...) {
    char	msgstr[MAXTMSTPSTRLEN];
    va_list	argptr;

    va_start (argptr, formatstr);
    vsprintf (msgstr, formatstr, argptr);
    va_end (argptr);
    perror(msgstr);
    exit(1);
}


/*******************************************************************************
Parse up to a maximum of maxarg arguments of inputline. argtbl is poplulated
with pointers to the arguments, and these are null terminated. (So some of the
contents of inputline are overwritten!)
*******************************************************************************/
int parse_input_line(char *inputline, char *argtbl[], int maxargs) {
    int		argidx;
    int		inquoteflag = 0;

    for (argidx=0; argidx<maxargs; argidx++) {	/* set all pointers to NULL */
	argtbl[argidx] = NULL;
    }
    argidx = 0;
    while(WHITESPACE(*inputline)) {
	inputline++;
    }
    while (*inputline) {
	if (*inputline == COMMENTCHAR) {
	    break;
	}
	if (*inputline == QUOTECHAR) {
	    inquoteflag = 1;
	    inputline++;
	} else {
	    inquoteflag = 0;
	}
	if (argidx < maxargs) {
	    argtbl[argidx++] = inputline++;
	} else {
	    break;
	}
	while (*inputline && (!WHITESPACE(*inputline) || inquoteflag)) {
	    if (*inputline == QUOTECHAR && inquoteflag) {
		break;
	    }
	    inputline++;
	}
	if (*inputline) {
	    *inputline++ = '\0';
	    while (WHITESPACE(*inputline)) {
		inputline++;
	    }
	}
    }
    return argidx;
}


/*******************************************************************************
Read the contents of the inputfile until the stanza header of the required type
is reached (reading and ignoring all lines up to that point).
*******************************************************************************/
void skip_to_stanza(char *stanza, char *inputline, int mandatoryflag) {
    int foundflag = 0;

    while (fgets(inputline, MAXINPUTLINELEN, inputfileptr)) {
	inputlinectr++;
	inputline[strlen(inputline)-1] = '\0';
	if (!strcmp(inputline, stanza)) {
	    foundflag = 1;
	    break;
	}
    }
    if (!foundflag && mandatoryflag) {
	fprintf(stderr, "Data file stanza '%s' not found, aborting!\n", stanza);
	exit(1);
    }
}


/*******************************************************************************
Set the paramtbl's values to the defaults. Note: these may be overwritten later
by entries in the configuration file.
*******************************************************************************/
void initialize_parameters() {
    Param	*paramptr;
    int		paramidx;

    for (paramidx=0; paramidx<(int)NUMCONFIGPARAMS; paramidx++) {
	paramptr = paramtbl+paramidx;

	/* Exit if the parameters are in the wrong order. (They MUST be!) */
	if (paramptr->idx != paramidx) {
	    fprintf(stderr,
	    "SNARK_IP1!: parameter '%s': index is %d, but must be %d, aborting!",
	    paramptr->paramname, paramptr->idx, paramidx);
	    exit(1);
	}

	/* set the param value = defaultvalue for every param in paramtbl */
	switch(paramptr->type) {
	    case CHAR:
		paramptr->value.character = paramptr->defaultvalue.character;
		break;
	    case INTEGER:
		paramptr->value.longint   = paramptr->defaultvalue.longint;
		break;
	    case FLTPNT:
		paramptr->value.fltpnt    = paramptr->defaultvalue.fltpnt;
		break;
	    case STRING:
		paramptr->value.string =
			    (char*)malloc(strlen(paramptr->defaultvalue.string)+1);
		strcpy(paramptr->value.string, paramptr->defaultvalue.string);
		break;
	    default:
		fprintf(stderr, "SNARK_IP2: illegal parameter type %d\n", paramptr->type);
		exit(1);
		break;
	}
    }
    /* fullscale is used a lot, so use a global variable */
    fullscale = paramtbl[FULLSCALEIDX].value.fltpnt;
}


/*******************************************************************************
Skip to the time values stanza and extract the count and iterations values.
*******************************************************************************/
void initialize_time_values() {
    char	inputline[MAXINPUTLINELEN], *argtbl[NUMTIMEVALUES];
    int		numargs;

    skip_to_stanza(TIMEVALUES, inputline, 1);

    while (fgets(inputline, MAXINPUTLINELEN, inputfileptr)) {
	inputlinectr++;
	if ((numargs=parse_input_line(inputline, argtbl, NUMTIMEVALUES)) == NUMTIMEVALUES) {
	    count    = atoi(argtbl[COUNTIDX]);
	    interval = atoi(argtbl[INTERVALIDX]);
	} else if (numargs == 0) {
	    break;
	} else {
	    fprintf(stderr, "Bad time values at line %d starting '%s', aborting!\n",
							    inputlinectr, argtbl[0]);
	    exit(1);
	}
    }
}


/*******************************************************************************
Skip to the METADATA stanza. For each class, dynamically allocate it's space
in table classtbl (as it grows) and populate it's data (name, type, start row).
Also dynamically allocate the space for each class' metrics (metrictbl), and
populate/initialize the metric's data (name, number, max, sum, numdevices,
devicetbl).
*******************************************************************************/
void initialize_metadata() {
    char	inputline[MAXINPUTLINELEN], *argtbl[MAXNUMMETADATA];
    Class	*classptr;
    Metric	*metricptr;
    int		numargs, startrow, metricidx;
    int		classidx = 0;

    skip_to_stanza(METADATASTR, inputline, 1);

    /* Loop through the classes */
    while (fgets(inputline, MAXINPUTLINELEN, inputfileptr)) {
	inputlinectr++;
	if ((numargs=parse_input_line(inputline, argtbl, MAXNUMMETADATA)) >= NUMMETAITEMS+1) {

	    if (*argtbl[CLASSTYPEIDX] != VECTORCLASS && *argtbl[CLASSTYPEIDX] !=
									ARRAYCLASS) {
		fprintf(stderr,
		"Class '%s': bad type '%c': must be '%c' or '%c', aborting!\n",
			    argtbl[0], *argtbl[CLASSTYPEIDX], VECTORCLASS, ARRAYCLASS);
		exit(1);
	    }

	    startrow = atoi(argtbl[STARTROWIDX]);
	    if (startrow < 1 || startrow > count) {
		fprintf(stderr,
		"Class '%s': bad start row '%d': must be 1 to %d, aborting!\n",
							argtbl[0], startrow, count-1);
		exit(1);
	    }

	    if (classtbl == NULL) {
		if ((classtbl=calloc(1, sizeof(Class))) == NULL) {
		    err_exit("initialize_metadata: class calloc failed, aborting!");
		}
	    } else {
		if ((classtbl=realloc(classtbl, (classidx+1)*sizeof(Class))) == NULL) {
		    err_exit("initialize_metadata: class realloc failed, aborting!");
		}
	    }

	    classptr = classtbl+classidx;
	    strncpy(classptr->classname, argtbl[CLASSSTRIDX], MAXCLSNAMELEN);
	    classptr->classtype = *argtbl[CLASSTYPEIDX];
	    classptr->startrow = startrow-1;

	    if ((classptr->metrictbl=calloc(numargs-NUMMETAITEMS, sizeof(Metric))) == NULL) {
		err_exit("initialize_metadata: metric calloc for class '%s' failed, aborting!",
									classptr->classname);
	    }

	    for (metricidx=0; metricidx<numargs-NUMMETAITEMS; metricidx++) {
		metricptr = classptr->metrictbl+metricidx;
	    	strncpy(metricptr->metricname, argtbl[metricidx+NUMMETAITEMS], MAXMETNAMELEN);
		metricptr->number	= 0;
		metricptr->max		= 0;
		metricptr->sum		= 0;
		metricptr->numdevices   = 0;
		metricptr->devicetbl    = NULL;
	    }
	    classptr->nummetrics = numargs-NUMMETAITEMS;
	    classidx += 1;
	} else if (numargs == 0) {
	    break;
	} else {
	    fprintf(stderr, "Bad class '%s' metadata at line %d\n", argtbl[0], inputlinectr);
	}
    }
    numclasses = classidx;
}


/*******************************************************************************
Read to the first DATA stanza, extract the UTC time, and store that in the
global variable firsttimestamp. If the TZ parameter has been set in the config
file, (attempt to) set the environment variable TZ to that value.
*******************************************************************************/
void initialize_timestamp() {
    char	inputline[MAXINPUTLINELEN], *argtbl[NUMDATEARGS];
    int		numargs;
    int		firsttimesetctr = 0;

    skip_to_stanza(DATESTR, inputline, 1);

    while (fgets(inputline, MAXINPUTLINELEN, inputfileptr)) {
	inputlinectr++;

	if ((numargs=parse_input_line(inputline, argtbl, NUMDATEARGS)) == NUMDATEARGS) {
	    firsttimestamp = atol(argtbl[TIMESTAMPIDX]);
	    firsttimesetctr++;
	} else if (numargs == 0) {
	    break;
	} else {
	    fprintf(stderr, "initialize_timestamp: date error at line %d (%s)\n",
							    inputlinectr, inputline);
	}
    }

    if (firsttimesetctr != 1) {
	fprintf(stderr,
	    "firsttimestamp was set %d times at/near line %d; must be 1, aborting!\n",
							firsttimesetctr, inputlinectr);
	exit(1);
    }
}


/*******************************************************************************
Classes have metric(s) and metrics have device(s). Metric(s) of (single-row)
"vector" classes (which actually have no devices), store the data for that
metric in devicetbl[0].  add_device is called by initialize_classes to allocate
the space for devicetbl, save the device name and initialize (zero) the
numerical values.
*******************************************************************************/
void add_device(Metric *metricptr, char *devicename) {
    Device	*deviceptr;
    int		deviceidx, numdevices;
    int		newdeviceflag = 1;

    numdevices = metricptr->numdevices;
    for (deviceidx=0; deviceidx<numdevices; deviceidx++) {
	deviceptr = metricptr->devicetbl+deviceidx;
	if (!strncmp(devicename, deviceptr->devicename, MAXDEVNAMELEN)) { 
	    newdeviceflag = 0;
	}
    }

    if (newdeviceflag) {
	if (metricptr->devicetbl == NULL) {
	    if ((metricptr->devicetbl=calloc(1, sizeof(Device))) == NULL) {
		err_exit("add_device: device calloc for metric '%s' failed, aborting!",
								metricptr->metricname);
	    }
	} else {
	    if ((metricptr->devicetbl=realloc(metricptr->devicetbl,
				    (deviceidx+1)*sizeof(Device))) == NULL) {
		err_exit("add_device: device realloc for metric '%s' failed, aborting!",
								metricptr->metricname);
	    }
	}

	deviceptr = metricptr->devicetbl+deviceidx;
	strncpy(deviceptr->devicename, devicename, MAXDEVNAMELEN);
	deviceptr->number = 0;
	deviceptr->max	  = 0;
	deviceptr->sum	  = 0;
	deviceptr->scale  = 0;
	if ((deviceptr->valuetbl=(double*)calloc(count, sizeof(double))) == NULL) {
	    err_exit("add_device: value calloc for metric '%s' failed, aborting!",
								metricptr->metricname);
	}
	metricptr->numdevices++;
    }
}


/*******************************************************************************
Classes have metric(s) and metrics have device(s). initialize_classes loops
through the classes, skips to data for the current class, and calls add_device
for each device beloging to that class. Array classes really do have devices!
The data for each array class metric's device(s) is stored in that metric's
devicetbl[n]. Vector class metrics do NOT really have any devices, but they
still have data - it's stored in devicetbl[0] (for each metric of that vector
class).
*******************************************************************************/
void initialize_classes() {
    char inputline[MAXINPUTLINELEN], *argtbl[MAXNUMMETRICS+1], datastanza[MAXDATSTZLEN+1];
    Class	*classptr;
    int		classidx, numargs, metricidx;

    for (classidx=0; classidx<numclasses; classidx++) {	/* loop thru classes */
	classptr = classtbl+classidx;

	/* read a data line for this data stanza */
	sprintf(datastanza, "%s%c", classptr->classname, STANZATERMCHAR);
	skip_to_stanza(datastanza, inputline, 1);

	if (classptr->classtype == VECTORCLASS) {	/* vector (single-row) class */
	    /* 1 input file line: 1 "device" per metric!!! */
	    if (fgets(inputline, MAXINPUTLINELEN, inputfileptr)) {
		inputlinectr++;
		if ((numargs=parse_input_line(inputline, argtbl, MAXNUMMETRICS)) == 
							classptr->nummetrics) {
		    for (metricidx=0; metricidx<classptr->nummetrics; metricidx++) {
			add_device(classptr->metrictbl+metricidx, NODEVICENAME);
		    }
		} else {
		    fprintf(stderr, "Bad input file line starting '%s' at line %d\n",
							    inputline, inputlinectr);
		    fprintf(stderr, "%d vector metrics required, found %d, aborting\n",
						    classptr->nummetrics, numargs);
		    exit(1);
		}
	    }
	} else {					/* array (multi-row) class */
	    /* N input file line(s): N device(s) per metric!!! */
	    while (fgets(inputline, MAXINPUTLINELEN, inputfileptr)) {
		inputlinectr++;
		if ((numargs=parse_input_line(inputline, argtbl, MAXNUMMETRICS+1)) == 
							classptr->nummetrics+1) {
		    for (metricidx=0; metricidx<classptr->nummetrics; metricidx++) {
			add_device(classptr->metrictbl+metricidx, argtbl[0]);
		    }
		} else if (numargs == 0) {
		    break;
		} else {
		    fprintf(stderr, "Bad input file line starting '%s' at line %d\n",
							inputline, inputlinectr);
		    fprintf(stderr, "%d array metrics required, found %d, aborting\n",
						    classptr->nummetrics, numargs-1);
		    exit(1);
		}
	    }
	}
    }
    if (inputfileptr != stdin) {
	rewind(inputfileptr);
	inputlinectr = 0;
    }
}


/*******************************************************************************
Duplicate metric names (even if they are in different classes) are forbidden.
Abort if any are found.
*******************************************************************************/
void check_metric_names() {
    Class	*class1ptr, *class2ptr;
    Metric	*metric1ptr, *metric2ptr;
    int		class1idx, class2idx, metric1idx, metric2idx;

    for (class1idx=0; class1idx<numclasses; class1idx++) {
	class1ptr = classtbl+class1idx;
	for (metric1idx=0; metric1idx<class1ptr->nummetrics; metric1idx++) {
	    metric1ptr=class1ptr->metrictbl+metric1idx;
	    for (class2idx=0; class2idx<numclasses; class2idx++) {
		class2ptr = classtbl+class2idx;
		for (metric2idx=0; metric2idx<class2ptr->nummetrics; metric2idx++) {
		    metric2ptr=class2ptr->metrictbl+metric2idx;
		    if ((class1idx != class2idx || metric1idx != metric2idx) &&
			!strcmp(metric1ptr->metricname, metric2ptr->metricname)) {
			fprintf(stderr, "Duplicate metric '%s', aborting\n",
							    metric1ptr->metricname);
			exit(1);
		    }
		}
	    }
	}
    }
}


/*******************************************************************************
Read and parse a configuration file, which may contain maximum scale values for
metrics (e.g., cpu_us 100.0) and/or paramtbl vales (e.g., singlefiledelimiter '|').
Anything after the comment character ('#') is ignored.
*******************************************************************************/
void read_configfile() {
    char	inputline[MAXINPUTLINELEN], *argtbl[2];
    char	metric_device_name[MAXMETDEVNAMELEN];
    Class	*classptr;
    Metric	*metricptr;
    Device	*deviceptr;
    Param	*paramptr;
    int		numargs, classidx, metricidx, deviceidx, paramidx;
    int		legalparamflag;
    FILE	*configfileptr;

    if ((configfileptr=fopen(configfilename, "r")) == NULL) {
	err_exit("Could not open configuration file '%s', aborting!", configfilename);
    }

    while (fgets(inputline, MAXINPUTLINELEN, configfileptr)) {
	if ((numargs=parse_input_line(inputline, argtbl, 2)) == 2) {
	    legalparamflag = 0;

	    /* if a metric or a metric_device line has a scale value, grab it */
	    for (classidx=0; classidx<numclasses; classidx++) {	/* classes */
		classptr = classtbl+classidx;

		if (classptr->classtype == VECTORCLASS) { /* single-row vector class */
		    for (metricidx=0; metricidx<classptr->nummetrics; metricidx++) {
			metricptr=classptr->metrictbl+metricidx;
			if (!strcmp(argtbl[0], metricptr->metricname)) {
			    deviceptr=metricptr->devicetbl;
			    deviceptr->scale = atof(argtbl[1]);
			    legalparamflag = 1;
			}
		    }
		} else {				/* multi-row array class */
		    for (metricidx=0; metricidx<classptr->nummetrics; metricidx++) {
			metricptr=classptr->metrictbl+metricidx;

			if (!strcmp(argtbl[0], metricptr->metricname)) {
			    for (deviceidx=0; deviceidx<metricptr->numdevices;
									deviceidx++) {
				deviceptr=metricptr->devicetbl+deviceidx;
				deviceptr->scale = atof(argtbl[1]);
			    }
			    legalparamflag = 1;
			} else {
			    for (deviceidx=0; deviceidx<metricptr->numdevices;
									deviceidx++) {
				deviceptr=metricptr->devicetbl+deviceidx;
				sprintf(metric_device_name, "%s%s%s",
					metricptr->metricname,
					paramtbl[METDEVSEPARATORIDX].value.string,
					deviceptr->devicename);
				if (!strcmp(argtbl[0], metric_device_name)) {
				    deviceptr->scale = atof(argtbl[1]);
				    legalparamflag = 1;
				    break;
				}
			    }
			}
		    }
		}
	    }

	    /* Overwrite any paramtbl value with value(s) set in the config file */
	    for (paramidx=0; paramidx<(int)NUMCONFIGPARAMS; paramidx++) {
		paramptr = paramtbl+paramidx;
		if (!strcmp(argtbl[0], paramptr->paramname)) {
		    switch(paramptr->type) {
			case CHAR:    paramptr->value.character = *argtbl[1]; break;
			case FLTPNT:  paramptr->value.fltpnt    = atof(argtbl[1]); break;
			case INTEGER: paramptr->value.longint   = atoi(argtbl[1]); break;
			case STRING:
			    paramptr->value.string = (char*)malloc(strlen(argtbl[1]));
			    strcpy(paramptr->value.string, argtbl[1]);
			    break;
			default:
			    fprintf(stderr, "SNARK: read_configfile\n");
			    exit(1);
			    break;
		    }

		    legalparamflag = 1;
		    break;
		}
	    }

	    if (legalparamflag == 0) {
		fprintf(stderr, "Ignoring unknown configuraton file parameter '%s'\n", argtbl[0]);
	    }
	} else if (numargs != 0) {
	    fprintf(stderr, "Bad configuration file line starting '%s'\n", argtbl[0]);
	}
    }
    fclose(configfileptr);

    if (*paramtbl[TIMEZONEIDX].value.string != '\0') {
	setenv("TZ", paramtbl[TIMEZONEIDX].value.string, 1);
	tzset();
    }
}


/*******************************************************************************
Read and process a vector class stanza (of input file data), and update data
values, e.g., number, max, sum for both the metric and the device.
*******************************************************************************/
void read_vector_stanza(char* inputfilename, Class *classptr) {
    char	inputline[MAXINPUTLINELEN], *argtbl[MAXNUMMETRICS];
    Metric	*metricptr;
    Device	*deviceptr;
    double	value;
    int		numargs, metricidx;
    int		rowidx = 0;

    while (fgets(inputline, MAXINPUTLINELEN, inputfileptr)) {
	inputlinectr++;
	if ((numargs=parse_input_line(inputline, argtbl, MAXNUMMETRICS)) ==
							classptr->nummetrics) {
	    if (rowidx >= classptr->startrow) {
		for (metricidx=0; metricidx<classptr->nummetrics; metricidx++) {
		    value = atof(argtbl[metricidx]);
		    metricptr = classptr->metrictbl+metricidx;
		    metricptr->number++;
		    metricptr->max = MAX(metricptr->max, value);
		    metricptr->sum += value;
		    /* This _is_ required, at least for now! */ 
		    deviceptr = metricptr->devicetbl;
		    deviceptr->number++;
		    deviceptr->max = MAX(metricptr->max, value);
		    deviceptr->sum += value;
		    *(deviceptr->valuetbl+rowidx) = value;
		    /* This _is_ required, at least for now! */ 
		}
	    }
	} else if (numargs == 0) {
	    break;
	} else {
	    fprintf(stderr, "File %s line %d vector class %s: bad data starting '%s'\n",
		    inputfilename, inputlinectr, classptr->classname, inputline);
	}
	rowidx++;
    }
    if (rowidx != count) {
	fprintf(stderr, "File %s line %d vector class %s: expected %d rows, not %d\n",
			inputfilename, inputlinectr, classptr->classname, count, rowidx);
    }
}


/*******************************************************************************
Read and process an array class stanza (of input file data), and update data
values, e.g., number, max, sum for both the metric and the device.
*******************************************************************************/
void read_array_stanza(char* inputfilename, Class *classptr) {
    char	inputline[MAXINPUTLINELEN], *argtbl[MAXNUMMETRICS+1];
    Device	*deviceptr;
    double	value;
    int		numargs, metricidx, deviceidx;
    Metric	*metricptr = NULL;
    int		rowidx = 0;

    while (fgets(inputline, MAXINPUTLINELEN, inputfileptr)) {
	inputlinectr++;
	if ((numargs=parse_input_line(inputline, argtbl, MAXNUMMETRICS+1)) ==
							classptr->nummetrics+1) {
	    for (metricidx=0; metricidx<classptr->nummetrics; metricidx++) {
		metricptr = classptr->metrictbl+metricidx;
		if (rowidx/metricptr->numdevices >= classptr->startrow) {
		    value = atof(argtbl[metricidx+1]);
		    metricptr->number++;
		    metricptr->max = MAX(metricptr->max, value);
		    metricptr->sum += value;
		    deviceidx = rowidx % metricptr->numdevices;
		    deviceptr = metricptr->devicetbl+deviceidx;
		    deviceptr->number++;
		    deviceptr->max = MAX(deviceptr->max, value);
		    deviceptr->sum += value;
		    *(deviceptr->valuetbl+(rowidx/metricptr->numdevices)) = value;
		    /* integer division!!! ^^^^^^/^^^^^^^^^^^^^^^^^^^^^ */
		} else {
		    break;
		}
	    }
	} else if (numargs == 0) {
	    break;
	} else {
	    fprintf(stderr, "File %s line %d array class %s: bad data starting '%s'\n",
		    inputfilename, inputlinectr, classptr->classname, inputline);
	}
	rowidx++;
    }
    if (rowidx != count*metricptr->numdevices) {
	fprintf(stderr, "File %s line %d array class %s: expected %d rows, not %d\n",
				    inputfilename, inputlinectr, classptr->classname,
				    count*metricptr->numdevices, rowidx);
    }
}


/*******************************************************************************
Write the header (first line) to all of the "active" (scale != 0) metric and
metric_device files using formatting specified by the relevant paramtbl entry.
*******************************************************************************/
void output_singlefile_headers(FILE *singlefileptr) {
    Class	*classptr;
    Metric	*metricptr;
    Device	*deviceptr;
    int		classidx, metricidx, deviceidx;

    fprintf(singlefileptr, "Time");
    for (classidx=0; classidx<numclasses; classidx++) {	/* loop thru classes */
	classptr = classtbl+classidx;
	for (metricidx=0; metricidx<classptr->nummetrics; metricidx++) {
	    metricptr = classptr->metrictbl+metricidx;

	    if (classptr->classtype == VECTORCLASS) {
		deviceptr = metricptr->devicetbl;
		if (deviceptr->scale != 0) {
		    fprintf(singlefileptr, "%c%s",
				    paramtbl[SINGFILEDELIMITERIDX].value.character,
				    metricptr->metricname);
		}
	    } else {
		for (deviceidx=0; deviceidx<metricptr->numdevices; deviceidx++) {
		    deviceptr = metricptr->devicetbl+deviceidx;
		    if (deviceptr->scale != 0) {
			fprintf(singlefileptr, "%c%s%s%s",
				    paramtbl[SINGFILEDELIMITERIDX].value.character,
				    metricptr->metricname,
				    paramtbl[METDEVSEPARATORIDX].value.string,
				    deviceptr->devicename);
		    }
		}
	    }
	}
    }
    fprintf(singlefileptr, "\n");
}


/*******************************************************************************
Write the data for all of the current stanzas for all active (scale != 0)
metrics and metric_devices to a single file.
*******************************************************************************/
void output_singlefile_body(FILE *singlefileptr, time_t timestamp) {
    Class	*classptr;
    Metric	*metricptr;
    Device	*deviceptr;
    int		rowidx, classidx, metricidx, deviceidx;
    char	timestampstr[MAXTMSTPSTRLEN];
    struct tm	*timestampstructptr;
    time_t	rowtimestamp;
    double	*valueptr;

    for (rowidx=0; rowidx<count; rowidx++) {
	rowtimestamp = timestamp+(rowidx+1)*interval;
					    /* NOT UTC!!! the collector timezone!!! */
	timestampstructptr = localtime(&rowtimestamp);
	strftime(timestampstr, MAXTMSTPSTRLEN,
			paramtbl[SINGFILEDATEFMTIDX].value.string, timestampstructptr);
	fprintf(singlefileptr, "%s", timestampstr);

	for (classidx=0; classidx<numclasses; classidx++) {	/* loop thru classes */
	    classptr = classtbl+classidx;

	    for (metricidx=0; metricidx<classptr->nummetrics; metricidx++) {
		metricptr = classptr->metrictbl+metricidx;

		if (classptr->classtype == VECTORCLASS) {
		    deviceptr = metricptr->devicetbl;
		    if (deviceptr->scale != 0) {
			valueptr=deviceptr->valuetbl;
			if (rowidx >= classptr->startrow) {
			    fprintf(singlefileptr, "%c%.1f",
				paramtbl[SINGFILEDELIMITERIDX].value.character,
				fullscale / deviceptr->scale * valueptr[rowidx]);
			} else {
			    fprintf(singlefileptr, "%c",
				    paramtbl[SINGFILEDELIMITERIDX].value.character);
			}
		    }
		} else {
		    for (deviceidx=0; deviceidx<metricptr->numdevices; deviceidx++) {
			deviceptr = metricptr->devicetbl+deviceidx;
			if (deviceptr->scale != 0) {
			    valueptr=deviceptr->valuetbl;
			    if (rowidx >= classptr->startrow) {
				fprintf(singlefileptr, "%c%.1f",
				    paramtbl[SINGFILEDELIMITERIDX].value.character,
				    fullscale / deviceptr->scale * valueptr[rowidx]);
			    } else {
				fprintf(singlefileptr, "%c",
				    paramtbl[SINGFILEDELIMITERIDX].value.character);
			    }
			}
		    }
		}
	    }
	}
	fprintf(singlefileptr, "\n");
    }
}


/*******************************************************************************
Open one multi file output file. (It will be truncated if it already exists!!!)
*******************************************************************************/
FILE* open_multifile(char* filerelpath) {
    FILE	*fileptr;

    if ((fileptr=fopen(filerelpath, "w")) == NULL) {
	err_exit("Could not create/open file '%s', aborting!", filerelpath);
    }
    return fileptr;
}


/*******************************************************************************
If the multifiledirname directory does not exist, create it. Then open a multi
output file for each metric (and metric_device) whose scale is not zero. If the
file already exists, truncate it.
*******************************************************************************/
void prepare_multi_output_files(char *multifiledirname) {
    char	filerelpath[MAXPATHNAMELEN], formatstr[MAXFORMATSTRLEN];
    char	metric_device_name[MAXMETDEVNAMELEN];
    struct stat	statbuf;
    Class	*classptr;
    Metric	*metricptr;
    Device	*deviceptr;
    int		classidx, metricidx, deviceidx;

    if (multifiledirname == NULL) {
	return;
    }

    if (stat(multifiledirname, &statbuf) != 0) {	/* if multifiledirname does not exist, */
	if (mkdir(multifiledirname, MULTIDIRMODE) != 0) {	/* create it */
	    err_exit("Could not create/open directory '%s', aborting!", multifiledirname);
	}
	stat(multifiledirname, &statbuf);		/* and get it's details */
    }

    if ((statbuf.st_mode&S_IFMT) != S_IFDIR || (statbuf.st_mode&S_IWUSR) == 0) {
	fprintf(stderr, "'%s' is not a writable directory, aborting\n", multifiledirname);
	exit(1);
    }

    for (classidx=0; classidx<numclasses; classidx++) {	/* loop through the classes */
	classptr = classtbl+classidx;
	for (metricidx=0; metricidx<classptr->nummetrics; metricidx++) {
	    metricptr=classptr->metrictbl+metricidx;
	    if (classptr->classtype == VECTORCLASS) {
		deviceptr = metricptr->devicetbl;
		if (deviceptr->scale != 0) {
		    sprintf(filerelpath, "%s/%s", multifiledirname, metricptr->metricname);
		    deviceptr->fileptr = open_multifile(filerelpath);

		    sprintf(formatstr, "%s\n", paramtbl[MULTIFILEHEADERFMTIDX].value.string);
		    fprintf(deviceptr->fileptr, formatstr, metricptr->metricname,
									deviceptr->scale);
		}
	    } else {
		for (deviceidx=0; deviceidx<metricptr->numdevices; deviceidx++) {
		    deviceptr = metricptr->devicetbl+deviceidx;
		    if (deviceptr->scale != 0) {
			sprintf(filerelpath, "%s/%s%s%s", multifiledirname, metricptr->metricname,
				    paramtbl[METDEVSEPARATORIDX].value.string,
				    deviceptr->devicename);
			deviceptr->fileptr = open_multifile(filerelpath);
			sprintf(metric_device_name, "%s%s%s", metricptr->metricname,
				paramtbl[METDEVSEPARATORIDX].value.string, deviceptr->devicename);
			sprintf(formatstr, "%s\n", paramtbl[MULTIFILEHEADERFMTIDX].value.string);
			fprintf(deviceptr->fileptr, formatstr, metric_device_name,
									deviceptr->scale);
		    }
		}
	    }
	}
    }
    sprintf(filerelpath, "%s/%s", multifiledirname,
				    paramtbl[CLOCKTICKSFILENAMEIDX].value.string);
    clockticksfileptr = open_multifile(filerelpath);
}


/*******************************************************************************
Write the data for all of the current stanzas for all active (scale != 0)
metrics and metric_devices to all the relevant multiple file output files.
*******************************************************************************/
void output_multifile_bodies_data(time_t timestamp) {
    Class	*classptr;
    Metric	*metricptr;
    Device	*deviceptr;
    int		rowidx, classidx, metricidx, deviceidx;
    char	timestampstr[MAXTMSTPSTRLEN];
    struct tm	*timestampstructptr;
    time_t	rowtimestamp;
    double	*valueptr;

    for (rowidx=0; rowidx<count; rowidx++) {
	rowtimestamp = timestamp+(rowidx+1)*interval;
	timestampstructptr = localtime(&rowtimestamp);
	strftime(timestampstr, MAXTMSTPSTRLEN,
			paramtbl[MULTIFILEDATEFMTIDX].value.string, timestampstructptr);

	for (classidx=0; classidx<numclasses; classidx++) {	/* loop thru classes */
	    classptr = classtbl+classidx;
	    for (metricidx=0; metricidx<classptr->nummetrics; metricidx++) {
		metricptr = classptr->metrictbl+metricidx;

		if (classptr->classtype == VECTORCLASS) {
		    deviceptr = metricptr->devicetbl;
		    if (deviceptr->scale != 0) {
			valueptr=deviceptr->valuetbl;
			if (rowidx >= classptr->startrow) {
			    fprintf(deviceptr->fileptr, "%s%c%.1f\n", timestampstr,
				paramtbl[MULTIFILEDELIMITERIDX].value.character,
				fullscale / deviceptr->scale * valueptr[rowidx]);
			}
		    }
		} else {
		    for (deviceidx=0; deviceidx<metricptr->numdevices; deviceidx++) {
			deviceptr = metricptr->devicetbl+deviceidx;
			if (deviceptr->scale != 0) {
			    valueptr=deviceptr->valuetbl;
			    if (rowidx >= classptr->startrow) {
				fprintf(deviceptr->fileptr, "%s%c%.1f\n", timestampstr,
				paramtbl[MULTIFILEDELIMITERIDX].value.character,
				fullscale / deviceptr->scale * valueptr[rowidx]);
			    }
			}
		    }
		}
	    }
	}
    }
}


/*******************************************************************************
Clockticks is a special "extra" multiple file output file that contains data
that is useful for visualizing the time scale for graphical utilities that don't
handle a time axis well (such as xgraph).
*******************************************************************************/
void populate_clockticks(time_t lasttimestamp) {
    char	formatstr[MAXFORMATSTRLEN];
    time_t	clockticktbl[NUMCLOCKTICKSLEVELS], begtimestamp, endtimestamp, timestamp;
    struct tm	*timestampstructptr;
    Param	*paramptr;
    int		paramidx, levelidx, clockticktime;
    int		levelctr = 0;
    time_t	minclocktick = 10*365*24*60*60;	/* insanely unusably large value */

    for (paramidx=CLOCKTICKSLEV0IDX; paramidx<=CLOCKTICKSLEV7IDX; paramidx++) {
	paramptr = paramtbl+paramidx;
	if (paramptr->value.longint > 0) {
	    clockticktbl[levelctr] = paramptr->value.longint;
	    minclocktick = MIN(paramptr->value.longint, minclocktick);

	    /* ensure all non-zero clocktick levels are multiples of each other */
	    if (levelctr > 0 && (clockticktbl[levelctr-1] % clockticktbl[levelctr] != 0)) {
		fprintf(stderr,
			"clockticks level %d (%ld) is not a multple of level %d (%ld)\n",
			levelctr-1, clockticktbl[levelctr-1], levelctr, clockticktbl[levelctr]);
		return;
	    }
	    levelctr++;
	} else {	/* exit at first non-positive value */
	    break;
	}
    }
    if (levelctr == 0) {
	fprintf(stderr, "No valid clockticks levels specified!\n");
    }

    sprintf(formatstr, "%s\n", paramtbl[MULTIFILEHEADERFMTIDX].value.string);
    fprintf(clockticksfileptr, formatstr, paramtbl[CLOCKTICKSFILENAMEIDX].value.string,
									    fullscale);
    /* Begin the clockticks a bit before the first data, and ... */
    begtimestamp = firsttimestamp/minclocktick*minclocktick;
    /* end them a bit after the last data */
    endtimestamp = ((lasttimestamp+count*interval)/minclocktick+1)*minclocktick;

    for (timestamp=begtimestamp; timestamp<=endtimestamp; timestamp+=minclocktick) {
	timestampstructptr = localtime(&timestamp);
	clockticktime = 3600*timestampstructptr->tm_hour + 60*timestampstructptr->tm_min +
							    timestampstructptr->tm_sec;
	for (levelidx=0; levelidx<levelctr; levelidx++) {
	    if (clockticktime % clockticktbl[levelidx] == 0) {
		strftime(formatstr, MAXTMSTPSTRLEN,
			paramtbl[MULTIFILEDATEFMTIDX].value.string, timestampstructptr);
		fprintf(clockticksfileptr, "%s 0\n",  formatstr);
		fprintf(clockticksfileptr, "%s %d\n", formatstr, 2*(levelidx-levelctr));
		break;
	    }
	}
    }
}


/*******************************************************************************
Open the single file output file, if one has been specified.
*******************************************************************************/
FILE* prepare_single_output_file(char *singlefilename) {
    FILE	*singlefileptr = NULL;

    if (singlefilename != NULL) { /* will be truncated if it already exists!!! */
	if ((singlefileptr=fopen(singlefilename, "w")) == NULL) {
	    err_exit("Could not open single output file '%s', aborting!", singlefilename);
	} else {
	    output_singlefile_headers(singlefileptr);
	}
    }
    return singlefileptr;
}


/*******************************************************************************
Read an input data file data stanza and output it in the single file and/or
multiple file formats.
*******************************************************************************/
time_t read_inputfile(char *inputfilename, char *singlefilename, FILE *singlefileptr, char *multifiledirname) {
    char	inputline[MAXINPUTLINELEN], datastanza[MAXDATSTZLEN+1];
    char	*argtbl[NUMDATEARGS];
    Class	*classptr;
    int		numargs, classidx;
    time_t	timestamp = 0;;

    inputlinectr = 0;
    while (1) {
	skip_to_stanza(DATESTR, inputline, 0);
	if (fgets(inputline, MAXINPUTLINELEN, inputfileptr)) {
	    inputlinectr++;

	    if ((numargs=parse_input_line(inputline, argtbl, NUMDATEARGS)) == NUMDATEARGS) {
		timestamp = atol(argtbl[TIMESTAMPIDX]);
	    } else {
		fprintf(stderr, "read_inputfile: date error at input file %s line %d: %s",
						inputfilename, inputlinectr, inputline);
	    }

	    for (classidx=0; classidx<numclasses; classidx++) {
		classptr = classtbl+classidx;
		sprintf(datastanza, "%s%c", classptr->classname, STANZATERMCHAR);
		skip_to_stanza(datastanza, inputline, 0);

		if (classptr->classtype == VECTORCLASS) {
		    read_vector_stanza(inputfilename, classptr);
		} else {
		    read_array_stanza(inputfilename, classptr);
		}
	    }
	    if (singlefilename != NULL) {
		output_singlefile_body(singlefileptr, timestamp);
	    }
	    if (multifiledirname != NULL) {
		output_multifile_bodies_data(timestamp);
	    }
	} else {
	    break;
	}
    }
    return timestamp;
}


/*******************************************************************************
Output the data summary (maximum, average, and count) for all the metrics and
all metric_device entries (even if their scale value is 0).
*******************************************************************************/
void output_data_values_summary() {
    char	metric_device_name[MAXMETDEVNAMELEN];
    Class	*classptr;
    Metric	*metricptr;
    Device	*deviceptr;
    int		classidx, metricidx, deviceidx;

    printf("### Summary Data ################### Max ################# Avg ######### Num\n");
    for (classidx=0; classidx<numclasses; classidx++) {	/* loop thru classes */
	classptr = classtbl+classidx;
	for (metricidx=0; metricidx<classptr->nummetrics; metricidx++) {
	    metricptr=classptr->metrictbl+metricidx;

	    if (classptr->classtype == VECTORCLASS) {
		printf("# %-18s  %18.1f #  %18.1f %13d\n", metricptr->metricname,
				metricptr->max, metricptr->sum/metricptr->number,
				metricptr->number);
	    } else {
		printf("# %-18s  %18.1f #  %18.1f %13d\n", metricptr->metricname,
				metricptr->max, metricptr->sum/metricptr->number,
				metricptr->number);

		for (deviceidx=0; deviceidx<metricptr->numdevices; deviceidx++) {
		    deviceptr=metricptr->devicetbl+deviceidx;

		    sprintf(metric_device_name, "%s%s%s", metricptr->metricname,
				    paramtbl[METDEVSEPARATORIDX].value.string,
				    deviceptr->devicename);

		    printf("## %-18s %18.1f ## %18.1f %13d\n", metric_device_name,
				deviceptr->max, deviceptr->sum/deviceptr->number,
				deviceptr->number);
		}
	    }
	}
    }
    fflush(stdout);
}


/*******************************************************************************
Output the contents of paramtbl to stdout.
*******************************************************************************/
void output_paramtbl() {
    char	configvaluestr[MAXPARAMVALLEN], defaultvaluestr[MAXPARAMVALLEN];
    Param	*paramptr;
    int		paramidx;

    printf("# %-25s %-25s %-25s\n", "Parameter", "Active Value", "Default Value");
    printf("# ------------------------- ------------------------- -------------------------\n");
    for (paramidx=0; paramidx<(int)NUMCONFIGPARAMS; paramidx++) {
	paramptr = paramtbl+paramidx;
	switch(paramptr->type) {
	    case CHAR:
		sprintf(configvaluestr,  "%c%c%c", QUOTECHAR, paramptr->value.character,
										QUOTECHAR);
		sprintf(defaultvaluestr, "%c%c%c", QUOTECHAR, paramptr->defaultvalue.character,
										QUOTECHAR);
		break;
	    case FLTPNT:
		sprintf(configvaluestr,  "%c%.1f%c", QUOTECHAR, paramptr->value.fltpnt,
										QUOTECHAR);
		sprintf(defaultvaluestr, "%c%.1f%c", QUOTECHAR, paramptr->defaultvalue.fltpnt,
										QUOTECHAR);
		break;
	    case INTEGER:
		sprintf(configvaluestr,  "%c%ld%c", QUOTECHAR, paramptr->value.longint,
										QUOTECHAR);
		sprintf(defaultvaluestr, "%c%ld%c", QUOTECHAR, paramptr->defaultvalue.longint,
										QUOTECHAR);
		break;
	    case STRING:
		sprintf(configvaluestr,  "%c%s%c", QUOTECHAR, paramptr->value.string,
										QUOTECHAR);
		sprintf(defaultvaluestr, "%c%s%c", QUOTECHAR, paramptr->defaultvalue.string,
										QUOTECHAR);
		break;
	    default:
		printf("SNARK:");
		break;
	}
	printf("# %-25s %-25s # %-25s\n", paramptr->paramname,
						    configvaluestr, defaultvaluestr);
    }
}


/*******************************************************************************
If >1 configuration file, >1 singlefilename, or >1 multifiledirname is
specified, all but the last one (of each) is ignored.
*******************************************************************************/
int main(int argc, char *argv[]) {
    int		optionchar, optionidx;
    FILE	*singlefileptr;
    char	*singlefilename   = NULL;
    char	*multifiledirname = NULL;
    time_t	lasttimestamp = 0;
    int		firstfileflag = 1;
    static struct option long_options[] = {
	{"configurationfile",  required_argument, 0,  'c' },
	{"singlefile",         required_argument, 0,  's' },
	{"multifiledirectory", required_argument, 0,  'm' },
	{"datavalues",         no_argument,       0,  'd' },
	{"parameters",         no_argument,       0,  'p' },
	{"verbose",            no_argument,       0,  'v' },
	{"help",               no_argument,       0,  'h' },
	{0,                    0,                 0,  0   },
    };

    setlocale(LC_ALL, getenv("LANG"));

    while (1) {
	optionchar = getopt_long(argc, argv, "c:s:m:dpvh", long_options, &optionidx);
	if (optionchar == -1) {
	    break;
	}

	switch (optionchar) {
	    case 'c': configfilename   = optarg;		break; 
	    case 's': singlefilename   = optarg;		break; 
	    case 'm': multifiledirname = optarg;		break; 
	    case 'd': datavaluesflag   = 1;			break; 
	    case 'p': parametersflag   = 1;			break; 
	    case 'v': verbosity++;				break; 
	    case 'h':
	    case '?': display_usage_message(argv[0]); exit(0);	break; 
	}
    }

    if (optind >= argc) {
	display_usage_message(argv[0]);
	exit(1);
    }

    if (singlefilename == NULL && multifiledirname == NULL) {
	fprintf(stderr, "W: no output file has been specfied!\n");
    }

    while (optind < argc) {
	if (verbosity > 1) {
	    fprintf(stderr, "i: Processing input file '%s'\n", argv[optind]);
	}

	if (!strcmp(argv[optind], STDINFILENAME)) {
	    inputfileptr = stdin;
	    if (firstfileflag && verbosity > 0) {
		fprintf(stderr,
		"i: First data set skipped when using %s (stdin) as the FIRST input file\n", 
										STDINFILENAME);
	    }
	} else if ((inputfileptr=fopen(argv[optind], "r")) == NULL) {
	    fprintf(stderr, "E: Could not open input file '%s', skipping\n", argv[optind]);
	    optind++;
	    continue;
	}

	if (firstfileflag) {
	    initialize_parameters();
	    initialize_time_values();
	    initialize_metadata();
	    initialize_timestamp();
	    initialize_classes();	/* rewinds non-stdin files */
	    if (configfilename != NULL) {
		read_configfile();	/* optionally sets TZ  */
	    }
	    check_metric_names();
	    singlefileptr = prepare_single_output_file(singlefilename);
	    prepare_multi_output_files(multifiledirname);
	    firstfileflag = 0;
	}
	lasttimestamp = read_inputfile(argv[optind], singlefilename, singlefileptr, multifiledirname);
	fclose(inputfileptr);
	optind++;
    }

    if (multifiledirname != NULL && clockticksfileptr != NULL) {
	populate_clockticks(lasttimestamp);
    }

    if (parametersflag != 0) {
	output_paramtbl();
    }

    if (datavaluesflag != 0) {
	output_data_values_summary();
    }
    exit(0);
}
