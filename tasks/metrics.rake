namespace :metrics do
  task :lines do
    lines = 0
    codelines = 0
    total_lines = 0
    total_codelines = 0
    FileList["lib/**/*.rb"].each do |file_name|
      f = File.open file_name
      while line = f.gets
        lines += 1
        next if line =~ /^\s*$/
        next if line =~ /^\s*#/
        codelines += 1
      end
      puts "L: #{format '%4d', lines}, " \
           "LOC #{format '%4d', codelines} | #{file_name}"
      total_lines     += lines
      total_codelines += codelines

      lines = 0
      codelines = 0
    end

    puts "Code: Lines #{total_lines}, LOC #{total_codelines}\n\n"

    lines = 0
    codelines = 0
    total_lines = 0
    total_codelines = 0
    FileList["spec/**/*_spec.rb"].each do |file_name|
      f = File.open file_name
      while line = f.gets
        lines += 1
        next if line =~ /^\s*$/
        next if line =~ /^\s*#/
        codelines += 1
      end
      puts "L: #{format '%4d', lines}, " \
           "LOC #{format '%4d', codelines} | #{file_name}"
      total_lines     += lines
      total_codelines += codelines

      lines = 0
      codelines = 0
    end

    puts "Specs: Lines #{total_lines}, LOC #{total_codelines}\n\n"
  end
end
